#include "linux/delay.h"
#include "linux/fs.h"
#include "linux/kernel.h"
#include "linux/list.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#include "kernel_compat.h"

#define FILE_MAGIC 0x7f4b5355 // ' KSU', u32
#define FILE_FORMAT_VERSION 1 // u32

static DEFINE_MUTEX(allowlist_mutex);

// default profiles, these may be used frequently, so we cache it
static struct root_profile default_root_profile;
static struct non_root_profile default_non_root_profile;

static int allow_list_arr[PAGE_SIZE / sizeof(int)] __read_mostly __aligned(PAGE_SIZE);
static int allow_list_pointer __read_mostly = 0;

static void remove_uid_from_arr(uid_t uid)
{
	int *temp_arr;
	int i, j;

	if (allow_list_pointer == 0)
		return;

	temp_arr = kmalloc(sizeof(allow_list_arr), GFP_KERNEL);
	if (temp_arr == NULL) {
		pr_err("%s: unable to allocate memory\n", __func__);
		return;
	}

	for (i = j = 0; i < allow_list_pointer; i++) {
		if (allow_list_arr[i] == uid)
			continue;
		temp_arr[j++] = allow_list_arr[i];
	}

	allow_list_pointer = j;

	for (; j < ARRAY_SIZE(allow_list_arr); j++)
		temp_arr[j] = -1;

	memcpy(&allow_list_arr, temp_arr, PAGE_SIZE);
	kfree(temp_arr);
}

static void init_default_profiles()
{
	default_root_profile.uid = 0;
	default_root_profile.gid = 0;
	default_root_profile.groups_count = 1;
	default_root_profile.groups[0] = 0;
	memset(&default_root_profile.capabilities, 0xff,
	       sizeof(default_root_profile.capabilities));
	default_root_profile.namespaces = 0;
	strcpy(default_root_profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);

	// This means that we will umount modules by default!
	default_non_root_profile.umount_modules = true;
}

struct perm_data {
	struct list_head list;
	uid_t uid;
	bool allow;
};

static struct list_head allow_list;

static uint8_t allow_list_bitmap[PAGE_SIZE] __read_mostly __aligned(PAGE_SIZE);
#define BITMAP_UID_MAX ((sizeof(allow_list_bitmap) * BITS_PER_BYTE) - 1)

#define KERNEL_SU_ALLOWLIST "/data/adb/ksu/.allowlist"

static struct work_struct ksu_save_work;
static struct work_struct ksu_load_work;

bool persistent_allow_list(void);

void ksu_show_allow_list(void)
{
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	pr_info("ksu_show_allow_list");
	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		pr_info("uid :%d, allow: %d\n", p->uid, p->allow);
	}
}

bool ksu_allow_uid(uid_t uid, bool allow, bool persist)
#ifdef CONFIG_KSU_DEBUG
static void ksu_grant_root_to_shell()
{
	struct app_profile profile = {
		.allow_su = true,
		.current_uid = 2000,
	};
	strcpy(profile.key, "com.android.shell");
	strcpy(profile.rp_config.profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);
	ksu_set_app_profile(&profile, false);
}
#endif

bool ksu_get_app_profile(struct app_profile *profile)
{
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	bool found = false;

	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		bool uid_match = profile->current_uid == p->profile.current_uid;
		if (uid_match) {
			// found it, override it with ours
			memcpy(profile, &p->profile, sizeof(*profile));
			found = true;
			goto exit;
		}
	}

exit:
	return found;
}

static inline bool forbid_system_uid(uid_t uid) {
	#define SHELL_UID 2000
	#define SYSTEM_UID 1000
	return uid < SHELL_UID && uid != SYSTEM_UID;
}

static bool profile_valid(struct app_profile *profile)
{
	if (!profile) {
		return false;
	}

	if (forbid_system_uid(profile->current_uid)) {
		pr_err("uid lower than 2000 is unsupported: %d\n", profile->current_uid);
		return false;
	}

	if (profile->version < KSU_APP_PROFILE_VER) {
		pr_info("Unsupported profile version: %d\n", profile->version);
		return false;
	}

	if (profile->allow_su) {
		if (profile->rp_config.profile.groups_count > KSU_MAX_GROUPS) {
			return false;
		}

		if (strlen(profile->rp_config.profile.selinux_domain) == 0) {
			return false;
		}
	}

	return true;
}

bool ksu_set_app_profile(struct app_profile *profile, bool persist)
{
	// find the node first!
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	bool result = false;
	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		if (uid == p->uid) {
			p->allow = allow;
			result = true;
			goto out;
		}
	}

	// not found, alloc a new node!
	p = (struct perm_data *)kmalloc(sizeof(struct perm_data), GFP_KERNEL);
	if (!p) {
		pr_err("alloc allow node failed.\n");
		return false;
	}
	p->uid = uid;
	p->allow = allow;

	pr_info("allow_uid: %d, allow: %d", uid, allow);

	list_add_tail(&p->list, &allow_list);

out:
	if (profile->current_uid <= BITMAP_UID_MAX) {
		if (profile->allow_su)
			allow_list_bitmap[profile->current_uid / BITS_PER_BYTE] |= 1 << (profile->current_uid % BITS_PER_BYTE);
		else
			allow_list_bitmap[profile->current_uid / BITS_PER_BYTE] &= ~(1 << (profile->current_uid % BITS_PER_BYTE));
	} else {
		if (profile->allow_su) {
			/*
			 * 1024 apps with uid higher than BITMAP_UID_MAX
			 * registered to request superuser?
			 */
			if (allow_list_pointer >= ARRAY_SIZE(allow_list_arr)) {
				pr_err("too many apps registered\n");
				WARN_ON(1);
				return false;
			}
			allow_list_arr[allow_list_pointer++] = profile->current_uid;
		} else {
			remove_uid_from_arr(profile->current_uid);
		}
	}
	result = true;

	// check if the default profiles is changed, cache it to a single struct to accelerate access.
	if (unlikely(!strcmp(profile->key, "$"))) {
		// set default non root profile
		memcpy(&default_non_root_profile, &profile->nrp_config.profile,
		       sizeof(default_non_root_profile));
	}

	if (unlikely(!strcmp(profile->key, "#"))) {
		// set default root profile
		memcpy(&default_root_profile, &profile->rp_config.profile,
		       sizeof(default_root_profile));
	}

	if (persist)
		persistent_allow_list();

	return result;
}

bool __ksu_is_allow_uid(uid_t uid)
{
	int i;

	if (unlikely(uid == 0)) {
		// already root, but only allow our domain.
		return is_ksu_domain();
	}

	if (forbid_system_uid(uid)) {
		// do not bother going through the list if it's system
		return false;
	}

	if (likely(uid <= BITMAP_UID_MAX)) {
		return !!(allow_list_bitmap[uid / BITS_PER_BYTE] & (1 << (uid % BITS_PER_BYTE)));
	} else {
		for (i = 0; i < allow_list_pointer; i++) {
			if (allow_list_arr[i] == uid)
				return true;
		}
	}

	return false;
}

bool ksu_get_allow_list(int *array, int *length, bool allow)
{
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	int i = 0;
	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		// pr_info("get_allow_list uid: %d allow: %d\n", p->uid, p->allow);
		if (p->allow == allow) {
			array[i++] = p->uid;
		}
	}
	*length = i;

	return true;
}

void do_persistent_allow_list(struct work_struct *work)
{
	u32 magic = FILE_MAGIC;
	u32 version = FILE_FORMAT_VERSION;
	struct perm_data *p = NULL;
	struct list_head *pos = NULL;
	loff_t off = 0;

	struct file *fp =
		ksu_filp_open_compat(KERNEL_SU_ALLOWLIST, O_WRONLY | O_CREAT, 0644);
	if (IS_ERR(fp)) {
		pr_err("save_allow_list create file failed: %ld\n", PTR_ERR(fp));
		return;
	}

	// store magic and version
	if (ksu_kernel_write_compat(fp, &magic, sizeof(magic), &off) != sizeof(magic)) {
		pr_err("save_allow_list write magic failed.\n");
		goto exit;
	}

	if (ksu_kernel_write_compat(fp, &version, sizeof(version), &off) !=
	    sizeof(version)) {
		pr_err("save_allow_list write version failed.\n");
		goto exit;
	}

	list_for_each (pos, &allow_list) {
		p = list_entry(pos, struct perm_data, list);
		pr_info("save allow list uid :%d, allow: %d\n", p->uid,
			p->allow);
		ksu_kernel_write_compat(fp, &p->uid, sizeof(p->uid), &off);
		ksu_kernel_write_compat(fp, &p->allow, sizeof(p->allow), &off);
	}

exit:
	filp_close(fp, 0);
}

void do_load_allow_list(struct work_struct *work)
{
	loff_t off = 0;
	ssize_t ret = 0;
	struct file *fp = NULL;
	u32 magic;
	u32 version;

#ifdef CONFIG_KSU_DEBUG
	// always allow adb shell by default
	ksu_grant_root_to_shell();
#endif

	// load allowlist now!
	fp = ksu_filp_open_compat(KERNEL_SU_ALLOWLIST, O_RDONLY, 0);
	if (IS_ERR(fp)) {
#ifdef CONFIG_KSU_DEBUG
		int errno = PTR_ERR(fp);
		if (errno == -ENOENT) {
			ksu_allow_uid(2000, true,
				      true); // allow adb shell by default
		} else {
			pr_err("load_allow_list open file failed: %ld\n",
			       PTR_ERR(fp));
		}
#else
		pr_err("load_allow_list open file failed: %ld\n", PTR_ERR(fp));
#endif
		return;
	}

	// verify magic
	if (ksu_kernel_read_compat(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
	    magic != FILE_MAGIC) {
		pr_err("allowlist file invalid: %d!\n", magic);
		goto exit;
	}

	if (ksu_kernel_read_compat(fp, &version, sizeof(version), &off) !=
	    sizeof(version)) {
		pr_err("allowlist read version: %d failed\n", version);
		goto exit;
	}

	pr_info("allowlist version: %d\n", version);

	while (true) {
		u32 uid;
		bool allow = false;
		ret = ksu_kernel_read_compat(fp, &uid, sizeof(uid), &off);
		if (ret <= 0) {
			pr_info("load_allow_list read err: %zd\n", ret);
			break;
		}
		ret = ksu_kernel_read_compat(fp, &allow, sizeof(allow), &off);

		pr_info("load_allow_uid: %d, allow: %d\n", uid, allow);

		ksu_allow_uid(uid, allow, false);
	}

exit:
	ksu_show_allow_list();
	filp_close(fp, 0);
}

void ksu_prune_allowlist(bool (*is_uid_exist)(uid_t, void *), void *data)
{
	struct perm_data *np = NULL;
	struct perm_data *n = NULL;

	bool modified = false;
	// TODO: use RCU!
	mutex_lock(&allowlist_mutex);
	list_for_each_entry_safe (np, n, &allow_list, list) {
		uid_t uid = np->uid;
		if (!is_uid_exist(uid, data)) {
			modified = true;
			pr_info("prune uid: %d\n", uid);
			list_del(&np->list);
			allow_list_bitmap[uid / BITS_PER_BYTE] &= ~(1 << (uid % BITS_PER_BYTE));
			remove_uid_from_arr(uid);
			smp_mb();
			kfree(np);
		}
	}
	mutex_unlock(&allowlist_mutex);

	if (modified) {
		persistent_allow_list();
	}
}

// make sure allow list works cross boot
bool persistent_allow_list(void)
{
	return ksu_queue_work(&ksu_save_work);
}

bool ksu_load_allow_list(void)
{
	return ksu_queue_work(&ksu_load_work);
}

void ksu_allowlist_init(void)
{
	int i;

	BUILD_BUG_ON(sizeof(allow_list_bitmap) != PAGE_SIZE);
	BUILD_BUG_ON(sizeof(allow_list_arr) != PAGE_SIZE);

	for (i = 0; i < ARRAY_SIZE(allow_list_arr); i++)
		allow_list_arr[i] = -1;

	INIT_LIST_HEAD(&allow_list);

	INIT_WORK(&ksu_save_work, do_persistent_allow_list);
	INIT_WORK(&ksu_load_work, do_load_allow_list);
}

void ksu_allowlist_exit(void)
{
	struct perm_data *np = NULL;
	struct perm_data *n = NULL;

	do_persistent_allow_list(NULL);

	// free allowlist
	mutex_lock(&allowlist_mutex);
	list_for_each_entry_safe (np, n, &allow_list, list) {
		list_del(&np->list);
		kfree(np);
	}
	mutex_unlock(&allowlist_mutex);
}
