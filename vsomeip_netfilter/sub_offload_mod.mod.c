#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd01eb0cb, "kmalloc_trace_noprof" },
	{ 0x122c3a7e, "_printk" },
	{ 0x9f031ccc, "init_net" },
	{ 0x3b8a8086, "nf_register_net_hook" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x9765b730, "nf_unregister_net_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0xe0d88dbb, "__alloc_skb" },
	{ 0x3abf4e88, "skb_put" },
	{ 0xd36dc10c, "get_random_u32" },
	{ 0xcd9db85e, "dev_get_by_name" },
	{ 0xdf7a9958, "__dev_queue_xmit" },
	{ 0x1cbe9efc, "kfree_skb_reason" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0xb0075aec, "kmalloc_caches" },
	{ 0x64f32516, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "15E58613568CBFB4BC3A943");
