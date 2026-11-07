//! Embedded deployment scripts for LTV.
//!
//! These scripts are compiled into the binary via `include_str!` and rendered
//! at runtime with profile-specific values.

pub const LTV_FILES: &str = include_str!("scripts/mkinitfs/ltv.files");
pub const LTV_MODULES: &str = include_str!("scripts/mkinitfs/ltv.modules");
pub const LTV_PACKAGES: &str = include_str!("scripts/mkinitfs/ltv.packages");
pub const LTV_HOOK: &str = include_str!("scripts/mkinitfs/ltv-hook.sh");
pub const LTV_COMMON: &str = include_str!("scripts/mkinitfs/ltv-common.sh");
pub const INITRAMFS_PATCH: &str = include_str!("scripts/mkinitfs/initramfs-init.patch");
pub const DEPLOY_SH: &str = include_str!("scripts/deploy/deploy.sh");
pub const DEPLOY_NOPATCH_SH: &str = include_str!("scripts/deploy/deploy_nopatch.sh");
pub const CMDLINE_TMPL: &str = include_str!("scripts/cmdline.txt.tmpl");

use crate::model::Profile;

/// Render kernel command line from template.
pub fn render_cmdline(p: &Profile) -> String {
    let mappers = p.targets_meta.iter()
        .map(|t| t.mapped_name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let ltv_uuids = p.targets_meta.iter()
        .map(|t| format!("ltv_{}={}", t.mapped_name, t.luks_uuid))
        .collect::<Vec<_>>()
        .join("\n");
    let root_mapper = p.targets_meta.iter()
        .min_by_key(|t| t.order)
        .map(|t| format!("root=/dev/mapper/{}", t.mapped_name))
        .unwrap_or_default();
    CMDLINE_TMPL
        .replace("{mappers}", &mappers)
        .replace("{ltv_uuids}", &ltv_uuids)
        .replace("{root}", &root_mapper)
}

/// Render deploy.sh with kernel version.
pub fn render_deploy_sh(kernel_version: &str) -> String {
    DEPLOY_SH.replace("{kernel_version}", kernel_version)
}

/// Render deploy_nopatch.sh with kernel version.
pub fn render_deploy_nopatch_sh(kernel_version: &str) -> String {
    DEPLOY_NOPATCH_SH.replace("{kernel_version}", kernel_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Profile, TargetMeta, HostKey, ResumePolicy};
    use uuid::Uuid;

    fn test_profile() -> Profile {
        Profile {
            uuid: Uuid::nil().into_bytes(),
            name: "test".into(),
            notes: "".into(),
            host: "1.2.3.4".into(),
            port: 22,
            username: "root".into(),
            initramfs_host_key: None,
            os_host_key: None,
            host_key_pinned_at: 0,
            client_public_key: vec![],
            targets_meta: vec![
                TargetMeta {
                    luks_uuid: "111832b4-5029-4439-8713-d5b928f44412".into(),
                    fallback_path: Some("/dev/vda4".into()),
                    mapped_name: "cryptroot".into(),
                    order: 0,
                    keyslot: Some(0),
                    token_id: None,
                },
                TargetMeta {
                    luks_uuid: "ac302374-1b08-4511-944b-ef1658dd909b".into(),
                    fallback_path: Some("/dev/vda5".into()),
                    mapped_name: "cryptdata".into(),
                    order: 1,
                    keyslot: Some(1),
                    token_id: None,
                },
            ],
            resume: ResumePolicy::default(),
            connect_timeout_s: 10,
            exec_timeout_s: 30,
            envelope_nonce: [0u8; 24],
            envelope_ciphertext: vec![],
        }
    }

    #[test]
    fn test_render_cmdline() {
        let p = test_profile();
        let out = render_cmdline(&p);
        assert!(out.contains("ltv_mappers=cryptroot,cryptdata"));
        assert!(out.contains("ltv_cryptroot=111832b4-5029-4439-8713-d5b928f44412"));
        assert!(out.contains("ltv_cryptdata=ac302374-1b08-4511-944b-ef1658dd909b"));
        assert!(out.contains("ip=dhcp"));
    }

    #[test]
    fn test_render_deploy_sh() {
        let out = render_deploy_sh("6.18.60-0-virt");
        assert!(out.contains("6.18.60-0-virt"));
        assert!(out.contains("virtio base cryptsetup ltv network"));
        assert!(out.contains("initramfs-init.patch"));
    }

    #[test]
    fn test_render_deploy_nopatch_sh() {
        let out = render_deploy_nopatch_sh("6.18.60-0-virt");
        assert!(out.contains("6.18.60-0-virt"));
        assert!(out.contains("virtio base cryptsetup ltv network"));
        assert!(!out.contains("initramfs-init.patch"));
    }
}