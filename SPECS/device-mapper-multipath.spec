%global package_speccommit bd297fa189a70081d838fe184638a802c5d786cf
%global usver 0.4.9
%global xsver 121
%global xsrel %{xsver}%{?xscount}%{?xshash}

Summary: Tools to manage multipath devices using device-mapper
Name: device-mapper-multipath
Version: 0.4.9
Release: %{?xsrel}%{?dist}
License: GPL+
Group: System Environment/Base
URL: http://christophe.varoqui.free.fr/

Source0: multipath-tools-130222.tar.gz
Source1: multipath.conf
Patch0: 0001-RH-dont_start_with_no_config.patch
Patch1: 0002-RH-multipath.rules.patch
Patch2: 0003-RH-Make-build-system-RH-Fedora-friendly.patch
Patch3: 0004-RH-multipathd-blacklist-all-by-default.patch
Patch4: 0005-RH-add-mpathconf.patch
Patch5: 0006-RH-add-find-multipaths.patch
Patch6: 0007-RH-add-hp_tur-checker.patch
Patch7: 0008-RH-revert-partition-changes.patch
Patch8: 0009-RH-RHEL5-style-partitions.patch
Patch9: 0010-RH-dont-remove-map-on-enomem.patch
Patch10: 0011-RH-deprecate-uid-gid-mode.patch
Patch11: 0012-RH-kpartx-msg.patch
Patch12: 0013-RHBZ-883981-cleanup-rpmdiff-issues.patch
Patch13: 0014-RH-handle-other-sector-sizes.patch
Patch14: 0015-RH-fix-output-buffer.patch
Patch15: 0016-RH-dont-print-ghost-messages.patch
Patch16: 0018-RH-fix-factorize.patch
Patch17: 0019-RH-fix-sockets.patch
Patch18: 0020-RHBZ-907360-static-pthread-init.patch
Patch19: 0021-RHBZ-919119-respect-kernel-cmdline.patch
Patch20: 0022-RH-multipathd-check-wwids.patch
Patch21: 0023-RH-multipath-wipe-wwid.patch
Patch22: 0024-RH-multipath-wipe-wwids.patch
Patch23: 0025-UPBZ-916668_add_maj_min.patch
Patch24: 0026-fix-checker-time.patch
Patch25: 0027-RH-get-wwid.patch
Patch26: 0028-RHBZ-929078-refresh-udev-dev.patch
Patch27: 0029-RH-no-prio-put-msg.patch
Patch28: 0030-RHBZ-916528-override-queue-no-daemon.patch
Patch29: 0031-RHBZ-957188-kpartx-use-dm-name.patch
Patch30: 0032-RHBZ-956464-mpathconf-defaults.patch
Patch31: 0033-RHBZ-829963-e-series-conf.patch
Patch32: 0034-RHBZ-851416-mpathconf-display.patch
Patch33: 0035-RHBZ-891921-list-mpp.patch
Patch34: 0036-RHBZ-949239-load-multipath-module.patch
Patch35: 0037-RHBZ-768873-fix-rename.patch
Patch36: 0038-RHBZ-799860-netapp-config.patch
Patch37: 0039-RH-detect-prio-fix.patch
Patch38: 0040-RH-bindings-fix.patch
Patch39: 0041-RH-check-for-erofs.patch
Patch40: 0042-UP-fix-signal-handling.patch
Patch41: 0043-RH-signal-waiter.patch
Patch42: 0044-RHBZ-976688-fix-wipe-wwids.patch
Patch43: 0045-RHBZ-977297-man-page-fix.patch
Patch44: 0046-RHBZ-883981-move-udev-rules.patch
Patch45: 0047-RHBZ-kpartx-read-only-loop-devs.patch
Patch46: 0048-RH-print-defaults.patch
Patch47: 0049-RH-remove-ID_FS_TYPE.patch
Patch48: 0050-RH-listing-speedup.patch
Patch49: 0051-UP-fix-cli-resize.patch
Patch50: 0052-RH-fix-bad-derefs.patch
Patch51: 0053-UP-fix-failback.patch
Patch52: 0054-UP-keep-udev-ref.patch
Patch53: 0055-UP-handle-quiesced-paths.patch
Patch54: 0056-UP-alua-prio-fix.patch
Patch55: 0057-UP-fix-tmo.patch
Patch56: 0058-UP-fix-failback.patch
Patch57: 0059-UP-flush-failure-queueing.patch
Patch58: 0060-UP-uevent-loop-udev.patch
Patch59: 0061-RH-display-find-mpaths.patch
Patch60: 0062-RH-dont-free-vecs.patch
Patch61: 0063-RH-fix-warning.patch
Patch62: 0064-RHBZ-1010040-fix-ID_FS-attrs.patch
Patch63: 0065-UPBZ-995538-fail-rdac-on-unavailable.patch
Patch64: 0066-UP-dos-4k-partition-fix.patch
Patch65: 0067-RHBZ-1022899-fix-udev-partition-handling.patch
Patch66: 0068-RHBZ-1034578-label-partition-devices.patch
Patch67: 0069-UPBZ-1033791-improve-rdac-checker.patch
Patch68: 0070-RHBZ-1036503-blacklist-td-devs.patch
Patch69: 0071-RHBZ-1031546-strip-dev.patch
Patch70: 0072-RHBZ-1039199-check-loop-control.patch
Patch71: 0073-RH-update-build-flags.patch
Patch72: 0074-RHBZ-1056976-dm-mpath-rules.patch
Patch73: 0075-RHBZ-1056976-reload-flag.patch
Patch74: 0076-RHBZ-1056686-add-hw_str_match.patch
Patch75: 0077-RHBZ-1054806-mpathconf-always-reload.patch
Patch76: 0078-RHBZ-1054044-fix-mpathconf-manpage.patch
Patch77: 0079-RHBZ-1070581-add-wwid-option.patch
Patch78: 0080-RHBZ-1075796-cmdline-wwid.patch
Patch79: 0081-RHBZ-1066264-check-prefix-on-rename.patch
Patch80: 0082-UPBZ-1109995-no-sync-turs-on-pthread_cancel.patch
Patch81: 0083-RHBZ-1080055-orphan-paths-on-reload.patch
Patch82: 0084-RHBZ-1110000-multipath-man.patch
Patch83: 0085-UPBZ-1110006-datacore-config.patch
Patch84: 0086-RHBZ-1110007-orphan-path-on-failed-add.patch
Patch85: 0087-RHBZ-1110013-config-error-checking.patch
Patch86: 0088-RHBZ-1069811-configurable-prio-timeout.patch
Patch87: 0089-RHBZ-1110016-add-noasync-option.patch
Patch88: 0090-UPBZ-1080038-reorder-paths-for-round-robin.patch
Patch89: 0091-RHBZ-1069584-fix-empty-values-fast-io-fail-and-dev-loss.patch
Patch90: 0092-UPBZ-1104605-reload-on-rename.patch
Patch91: 0093-UPBZ-1086825-user-friendly-name-remap.patch
Patch92: 0094-RHBZ-1086825-cleanup-remap.patch
Patch93: 0095-RHBZ-1127944-xtremIO-config.patch
Patch94: 0096-RHBZ-979474-new-wildcards.patch
Patch95: 0097-RH-fix-coverity-errors.patch
Patch96: 0098-UPBZ-1067171-mutipath-i.patch
Patch97: 0099-RH-add-all-devs.patch
Patch98: 0100-RHBZ-1067171-multipath-i-update.patch
Patch99: 0101-RH-cleanup-partmaps-code.patch
Patch100: 0102-RHBZ-631009-deferred-remove.patch
Patch101: 0103-RHBZ-1148979-fix-partition-mapping-creation-race-with-kpartx.patch
Patch102: 0104-RHBZ-1159337-fix-double-free.patch
Patch103: 0105-RHBZ-1180032-find-multipaths-man.patch
Patch104: 0106-RHBZ-1169935-no-new-devs.patch
Patch105: 0107-RH-adapter-name-wildcard.patch
Patch106: 0108-RHBZ-1153832-kpartx-remove-devs.patch
Patch107: 0109-RH-read-only-bindings.patch
Patch108: 0110-RHBZ-blacklist-vd-devs.patch
Patch109: 0111-RH-dont-show-pg-timeout.patch
Patch110: 0112-RHBZ-1194917-add-config_dir-option.patch
Patch111: 0113-RHBZ-1194917-cleanup.patch
Patch112: 0114-RHBZ-1196394-delayed-reintegration.patch
Patch113: 0115-RHBZ-1198418-fix-double-free.patch
Patch114: 0116-UPBZ-1188179-dell-36xxi.patch
Patch115: 0117-RHBZ-1198424-autodetect-clariion-alua.patch
Patch116: 0118-UPBZ-1200738-update-eternus-config.patch
Patch117: 0119-RHBZ-1081397-save-alua-info.patch
Patch118: 0120-RHBZ-1043093-realloc-fix.patch
Patch119: 0121-RHBZ-1197234-rules-fix.patch
Patch120: 0122-RHBZ-1212590-dont-use-var.patch
Patch121: 0123-UPBZ-1166072-fix-path-offline.patch
Patch122: 0124-RHBZ-1209275-retrigger-uevents.patch
Patch123: 0125-RHBZ-1153832-kpartx-delete.patch
Patch124: 0126-RHBZ-1211383-alias-collision.patch
Patch125: 0127-RHBZ-1201030-use-blk-availability.patch
Patch126: 0128-RHBZ-1222123-mpathconf-allow.patch
Patch127: 0129-UPBZ-1254292-iscsi-targetname.patch
Patch128: 0130-RHBZ-1259523-host_name_len.patch
Patch129: 0131-UPBZ-1259831-lock-retry.patch
Patch130: 0132-RHBZ-1296979-fix-define.patch
Patch131: 0133-RHBZ-1241774-sun-partition-numbering.patch
Patch132: 0134-RHBZ-1241528-check-mpath-prefix.patch
Patch133: 0135-RHBZ-1299600-path-dev-uevents.patch
Patch134: 0136-RHBZ-1304687-wait-for-map-add.patch
Patch135: 0137-RHBZ-1280524-clear-chkr-msg.patch
Patch136: 0138-RHBZ-1288660-fix-mpathconf-allow.patch
Patch137: 0139-RHBZ-1273173-queue-no-daemon-doc.patch
Patch138: 0140-RHBZ-1299647-fix-help.patch
Patch139: 0141-RHBZ-1303953-mpathpersist-typo.patch
Patch140: 0142-RHBZ-1283750-kpartx-fix.patch
Patch141: 0143-RHBZ-1299648-kpartx-sync.patch
Patch142: 0144-RHBZ-1299652-alua-pref-arg.patch
Patch143: 0145-UP-resize-help-msg.patch
Patch144: 0146-UPBZ-1299651-raw-output.patch
Patch145: 0147-RHBZ-1272620-fail-rm-msg.patch
Patch146: 0148-RHBZ-1292599-verify-before-remove.patch
Patch147: 0149-RHBZ-1292599-restore-removed-parts.patch
Patch148: 0150-RHBZ-1253913-fix-startup-msg.patch
Patch149: 0151-RHBZ-1297456-weighted-fix.patch
Patch150: 0152-RHBZ-1269293-fix-blk-unit-file.patch
Patch151: 0153-RH-fix-i686-size-bug.patch
Patch152: 0154-UPBZ-1291406-disable-reinstate.patch
Patch153: 0155-UPBZ-1300415-PURE-config.patch
Patch154: 0156-UPBZ-1313324-dont-fail-discovery.patch
Patch155: 0157-RHBZ-1319853-multipath-c-error-msg.patch
Patch156: 0158-RHBZ-1318581-timestamp-doc-fix.patch
Patch157: 0159-UPBZ-1255885-udev-waits.patch
Patch158: 0160-RH-udev-flags.patch
Patch159: 0161-RHBZ-1311659-no-kpartx.patch
Patch160: 0162-RHBZ-1333331-huawei-config.patch
Patch161: 0163-UPBZ-1333492-resize-map.patch
Patch162: 0164-RHBZ-1311463-dos-part-rollover.patch
Patch163: 0165-UPBZ-1341748-MSA-2040-conf.patch
Patch164: 0166-RHBZ-1323429-dont-allow-new-wwid.patch
Patch165: 0167-RHBZ-1335176-fix-show-cmds.patch
Patch166: 0168-RHBZ-1347769-shared-lock.patch
Patch167: 0169-UPBZ-1353357-json-output.patch
Patch168: 0170-UPBZ-1352925-fix-typo.patch
Patch169: 0171-UPBZ-1356651-allow-zero-size.patch
Patch170: 0172-RHBZ-1350931-no-active-add.patch
Patch171: 0173-RH-update-man-page.patch
Patch172: 0174-RHBZ-1362396-modprobe.patch
Patch173: 0175-RHBZ-1357382-ordering.patch
Patch174: 0176-RHBZ-1363830-fix-rename.patch
Patch175: 0177-libmultipath-correctly-initialize-pp-sg_id.patch
Patch176: 0178-libmultipath-add-rbd-discovery.patch
Patch177: 0179-multipath-tools-add-checker-callout-to-repair-path.patch
Patch178: 0180-multipath-tools-Add-rbd-checker.patch
Patch179: 0181-multipath-tools-Add-rbd-to-the-hwtable.patch
Patch180: 0182-multipath-tools-check-for-initialized-checker-before.patch
Patch181: 0183-multipathd-Don-t-call-repair-on-blacklisted-path.patch
Patch182: 0184-rbd-fix-sync-repair-support.patch
Patch183: 0185-rbd-check-for-nonshared-clients.patch
Patch184: 0186-rbd-check-for-exclusive-lock-enabled.patch
Patch185: 0187-rbd-fixup-log-messages.patch
Patch186: 0188-RHBZ-1368501-dont-exit.patch
Patch187: 0189-RHBZ-1368211-remove-retries.patch
Patch188: 0190-RHBZ-1380602-rbd-lock-on-read.patch
Patch189: 0191-RHBZ-1169168-disable-changed-paths.patch
Patch190: 0192-RHBZ-1362409-infinibox-config.patch
Patch191: 0194-RHBZ-1351964-kpartx-recurse.patch
Patch192: 0195-RHBZ-1359510-no-daemon-msg.patch
Patch193: 0196-RHBZ-1239173-dont-set-flag.patch
Patch194: 0197-RHBZ-1394059-max-sectors-kb.patch
Patch195: 0198-RHBZ-1372032-detect-path-checker.patch
Patch196: 0199-RHBZ-1279355-3pardata-config.patch
Patch197: 0200-RHBZ-1402092-orphan-status.patch
Patch198: 0201-RHBZ-1403552-silence-warning.patch
Patch199: 0202-RHBZ-1362120-skip-prio.patch
Patch200: 0203-RHBZ-1363718-add-msgs.patch
Patch201: 0204-RHBZ-1406226-nimble-config.patch
Patch202: 0205-RHBZ-1416569-reset-stats.patch
Patch203: 0206-RHBZ-1239173-pt2-no-paths.patch
Patch204: 0207-UP-add-libmpathcmd.patch
Patch205: 0208-UPBZ-1430097-multipathd-IPC-changes.patch
Patch206: 0209-UPBZ-1430097-multipath-C-API.patch
Patch207: 0210-RH-fix-uninstall.patch
Patch208: 0211-RH-strlen-fix.patch
Patch209: 0212-RHBZ-1431562-for-read-only.patch
Patch210: 0213-RHBZ-1430908-merge-dell-configs.patch
Patch211: 0214-RHBZ-1392115-set-paths-not-ready.patch
Patch212: 0215-RHBZ-1444194-fix-check-partitions.patch
Patch213: 0216-RHBZ-1448562-fix-reserve.patch
Patch214: 0217-RHBZ-1448576-3PAR-config.patch
Patch215: 0218-RHBZ-1459370-add-feature-fix.patch
Patch216: 0219-RHBZ-1448970-fix-resize.patch
Patch217: 0220-RHBZ-1448223-fix-kpartx.patch
Patch218: 0221-RH-harden-files.patch
Patch219: 0222-RHBZ-1457288-fix-show-maps-json.patch
Patch220: 0223-RHBZ-1452210-unpriv-sgio.patch
Patch221: 0224-RHBZ-1452210-prkey.patch
Patch222: 0225-RH-udevdir.patch
Patch223: 0226-RH-allow-overrides-section.patch
Patch224: 0227-RHBZ-1465773-fix-path-delay-msg.patch
Patch225: 0228-RHBZ-1464634-hauwei-config-update.patch
Patch226: 0229-RHBZ-1467987-poll-on-udev-monitor.patch
Patch227: 0230-UP-allow-invalid-creates.patch
Patch228: 0231-RHBZ-1458852-delay-readying.patch
Patch229: 0232-RHBZ-1456955-property-blacklist.patch
Patch230: 0233-RHBZ-1451852-1482629-nimble-config.patch
Patch231: 0234-RHBZ-1500109-doc-typo.patch
Patch232: 0235-RHBZ-1480638-NVMe-support.patch
Patch233: 0236-RHBZ-1525348-fix-msg.patch
Patch234: revert-0103.patch
Patch235: improve_error_handling_in_reconfigure.patch
Patch236: restrict_should_multipath_success_conditions.patch
Patch237: backport_21136f36a_Add-HP-MSA-2040-to-the-hardware-table.patch

# runtime
Requires: %{name}-libs = %{version}-%{release}
Requires: kpartx = %{version}-%{release}
Requires: device-mapper >= 7:1.02.96
Requires: initscripts
Requires(post): systemd-units systemd-sysv chkconfig
Requires(preun): systemd-units
Requires(postun): systemd-units

Provides: xenserver-multipath

# build/setup
BuildRequires: libaio-devel, device-mapper-devel >= 1.02.89
BuildRequires: libselinux-devel, libsepol-devel
BuildRequires: readline-devel, ncurses-devel
BuildRequires: systemd-units, systemd-devel
BuildRequires: json-c-devel, perl, pkgconfig
%ifarch x86_64
BuildRequires: librados2-devel
%endif
%{?_cov_buildrequires}

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
%{name} provides tools to manage multipath devices by
instructing the device-mapper multipath kernel module what to do.
The tools are :
* multipath - Scan the system for multipath devices and assemble them.
* multipathd - Detects when paths fail and execs multipath to update things.

%package libs
Summary: The %{name} modules and shared library
License: GPL+
Group: System Environment/Libraries

%description libs
The %{name}-libs provides the path checker
and prioritizer modules. It also contains the libmpathpersist and
libmpathcmd shared libraries, as well as multipath's internal library,
libmultipath.

%package devel
Summary: Development libraries and headers for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: %{name}-libs = %{version}-%{release}

%description devel
This package contains the files need to develop applications that use
device-mapper-multipath's lbmpathpersist and libmpathcmd libraries.

%package sysvinit
Summary: SysV init script for device-mapper-multipath
Group: System Environment/Libraries

%description sysvinit
SysV style init script for device-mapper-multipth. It needs to be
installed only if systemd is not used as the system init process.

%package -n kpartx
Summary: Partition device manager for device-mapper devices
Group: System Environment/Base

%description -n kpartx
kpartx manages partition creation and removal for device-mapper devices.

%package -n libdmmp
Summary: device-mapper-multipath C API library
Group: System Environment/Libraries
Requires: json-c
Requires: %{name} = %{version}-%{release}
Requires: %{name}-libs = %{version}-%{release}

%description -n libdmmp
This package contains the shared library for the device-mapper-multipath
C API library.

%package -n libdmmp-devel
Summary: device-mapper-multipath C API library headers
Group: Development/Libraries
Requires: pkgconfig
Requires: libdmmp = %{version}-%{release}

%description -n libdmmp-devel
This package contains the files needed to develop applications that use
device-mapper-multipath's libdmmp C API library

%prep
%autosetup -p1
cp %{SOURCE1} .
%{?_cov_prepare}

%build
%define _udevdir %{_prefix}/lib/udev/rules.d
%define _libmpathdir %{_libdir}/multipath
%define _pkgconfdir %{_libdir}/pkgconfig
%{?_cov_wrap} make %{?_smp_mflags} LIB=%{_lib}

%install
rm -rf %{buildroot}

make install \
    DESTDIR=%{buildroot} \
    bindir=%{_sbindir} \
    syslibdir=%{_libdir} \
    libdir=%{_libmpathdir} \
    rcdir=%{_initrddir} \
    unitdir=%{_unitdir} \
    includedir=%{_includedir} \
    pkgconfdir=%{_pkgconfdir}

# tree fix up
install -d %{buildroot}/etc/multipath

%{?_cov_install}

%clean
rm -rf %{buildroot}

%post
%systemd_post multipathd.service

%preun
%systemd_preun multipathd.service

%postun
if [ $1 -ge 1 ] ; then
    /sbin/multipathd forcequeueing daemon > /dev/null 2>&1 || :
fi
%systemd_postun_with_restart multipathd.service

%triggerun -- %{name} < 0.4.9-37
# make sure old systemd symlinks are removed after changing the [Install]
# section in multipathd.service from multi-user.target to sysinit.target
/bin/systemctl --quiet is-enabled multipathd.service >/dev/null 2>&1 && /bin/systemctl reenable multipathd.service ||:

%triggerpostun -n %{name}-sysvinit -- %{name} < 0.4.9-16
/sbin/chkconfig --add mdmonitor >/dev/null 2>&1 || :

%files
%defattr(-,root,root,-)
%{_sbindir}/multipath
%{_sbindir}/multipathd
%{_sbindir}/mpathconf
%{_sbindir}/mpathpersist
%{_unitdir}/multipathd.service
%{_mandir}/man5/multipath.conf.5.gz
%{_mandir}/man8/multipath.8.gz
%{_mandir}/man8/multipathd.8.gz
%{_mandir}/man8/mpathconf.8.gz
%{_mandir}/man8/mpathpersist.8.gz
%config %{_udevdir}/62-multipath.rules
%config %{_udevdir}/11-dm-mpath.rules
%doc AUTHOR COPYING FAQ
%doc multipath.conf
%dir /etc/multipath

%files libs
%defattr(-,root,root,-)
%doc AUTHOR COPYING
%{_libdir}/libmultipath.so
%{_libdir}/libmultipath.so.*
%{_libdir}/libmpathpersist.so.*
%{_libdir}/libmpathcmd.so.*
%dir %{_libmpathdir}
%{_libmpathdir}/*

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files devel
%defattr(-,root,root,-)
%doc AUTHOR COPYING
%{_libdir}/libmpathpersist.so
%{_libdir}/libmpathcmd.so
%{_includedir}/mpath_cmd.h
%{_includedir}/mpath_persist.h
%{_mandir}/man3/mpath_persistent_reserve_in.3.gz
%{_mandir}/man3/mpath_persistent_reserve_out.3.gz

%files sysvinit
%{_initrddir}/multipathd

%files -n kpartx
%defattr(-,root,root,-)
%{_sbindir}/kpartx
%{_mandir}/man8/kpartx.8.gz

%files -n libdmmp
%defattr(-,root,root,-)
%doc AUTHOR COPYING
%{_libdir}/libdmmp.so.*

%post -n libdmmp -p /sbin/ldconfig

%postun -n libdmmp -p /sbin/ldconfig

%files -n libdmmp-devel
%defattr(-,root,root,-)
%doc AUTHOR COPYING
%{_libdir}/libdmmp.so
%dir %{_includedir}/libdmmp
%{_includedir}/libdmmp/*
%{_mandir}/man3/dmmp_*
%{_mandir}/man3/libdmmp.h.3.gz
%{_pkgconfdir}/libdmmp.pc

%{?_cov_results_package}

%changelog
* Tue Oct 12 2021 Mark Syms <mark.syms@citrix.com> - 0.4.9-121
- CP-34141: add coverity macros
- Define static analysis

* Fri Dec 06 2019 Tim Smith <tim.smith@citrix.com> - 0.4.9-120
- Take over patchqueue

* Wed Jan 31 2018 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-119
- Add 0236-RHBZ-1525348-fix-msg.patch
  * reduced message serverity level
- Resolves: bz #1525348

* Fri Nov 17 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-118
- Modify 0224-RHBZ-1452210-prkey.patch
  * Improve error checking for mpathpersist
- Resolves: bz #1452210

* Thu Nov 16 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-117
- Modify 0235-RHBZ-1480638-NVMe-support.patch
  * remove overly-restrictive uevent filtering
- Resolves: bz #1480638

* Tue Oct 31 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-116
- Add 0235-RHBZ-1480638-NVMe-support.patch
  * adds support for multipathing NVMe devices
- Resolves: bz #1480638

* Tue Oct 10 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-115
- Add 0233-RHBZ-1451852-1482629-nimble-config.patch
- Add 0234-RHBZ-1500109-doc-typo.patch
- Remove old triggerun scriptlet (bz1470384)
- Resolves: bz #1451852, #1470384, #1482629, #1500109

* Tue Oct  3 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-114
- Add 0226-RH-allow-overrides-section.patch
  * This is a dummy section that exists to help the transition to RHEL8
- Add 0227-RHBZ-1465773-fix-path-delay-msg.patch
- Add 0228-RHBZ-1464634-hauwei-config-update.patch
- Add 0229-RHBZ-1467987-poll-on-udev-monitor.patch
  * Do poll first, so udev_monitor_receive_device doesn't return error when
    there is no uevent
- Add 0230-UP-allow-invalid-creates.patch
  * Allow creation of devices with no valid paths.
- Add 0231-RHBZ-1458852-delay-readying.patch
  * Add ghost_delay configuration option to delay device activation when only
    ghost paths exist.
- Add 0232-RHBZ-1456955-property-blacklist.patch
  * Add the "property" blacklist type.
- Resolves: bz #1456955, #1458852, #1464634, #1465773, #1467987

* Wed Sep 20 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-113
- Modify 0224-RHBZ-1452210-prkey.patch
  * fix errow with telling multipathd to set prkeys
- Add 0225-RH-udevdir.patch
  * fix rpmdiff complaint about udev rules installation
- Resolves: bz #1452210

* Tue Sep 19 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-112
- Modify 0191-RHBZ-1169168-disable-changed-paths.patch
  * man page fixup
- Modfiy 0197-RHBZ-1394059-max-sectors-kb.patch
  * man page fixup
- Modify 0205-RHBZ-1416569-reset-stats.patch
  * man page fixup
- Add 0218-RHBZ-1459370-add-feature-fix.patch
  * handle null feature string
- Add 0219-RHBZ-1448970-fix-resize.patch
  * if the resize fails, try to resume again with the old table.
- Add 0220-RHBZ-1448223-fix-kpartx.patch
  * gracefully fail when run on something other than a file or block device
- Add 0221-RH-harden-files.patch
  * change build parameters to use position independent code
- Add 0222-RHBZ-1457288-fix-show-maps-json.patch
  * handle running "show maps json" with no multipath devices present
- Add 0223-RHBZ-1452210-unpriv-sgio.patch
  * add unpriv_sgio configuration option to set unpriv_sgio on multipath device
    and paths
- Add 0224-RHBZ-1452210-prkey.patch
  * allow setting reservation_key to "file" to set and read keys from
    prkey_file. Also add new multipathd commands to modify the prkey file.
- Resolves: bz #1459370, #1448970, #1448223, #1457288, #1452210

* Mon May 15 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-111
- Remove 0217-RHBZ-1437329-blacklist-oracle-devs.patch
  * Incorrect change, and the bug is already fixed.
- Move 0218-RHBZ-1448576-3PAR-config.patch to
  0217-RHBZ-1448576-3PAR-config.patch
- Resolves: bz #1448576

* Fri May 12 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-110
- Add 0215-RHBZ-1444194-fix-check-partitions.patch
  * make sure kpartx partions match the correct device
- Add 0216-RHBZ-1448562-fix-reserve.patch
  * don't join threads that haven't been created
- Add 0217-RHBZ-1437329-blacklist-oracle-devs.patch
  * blacklist db2.* devices
- Add 0218-RHBZ-1448576-3PAR-config.patch
- Resolves: bz #1444194, #1448562, #1437329, #1448576

* Tue Apr 25 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-109
- Add 0214-RHBZ-1392115-set-paths-not-ready.patch
  * Set ENV{SYSTEMD_READY}="0" on multipath path devices
- Resolves: bz #1392115

* Tue Apr 25 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-108
- Add 0213-RHBZ-1430908-merge-dell-configs.patch
- Resolves: bz #1430908

* Mon Apr  3 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-107
- Modify 0197-RHBZ-1394059-max-sectors-kb.patch
  * Make multipath only change max_sectors_kb on creates. On reloads, it
    just makes sure the new path matches the multipath device.
- Refresh 0198-RHBZ-1372032-detect-path-checker.patch
- Refresh 0201-RHBZ-1403552-silence-warning.patch
- Refresh 0206-RHBZ-1239173-pt2-no-paths.patch
- Refresh 0207-UP-add-libmpathcmd.patch
- Refresh 0212-RHBZ-1431562-for-read-only.patch
- Resolves: bz #1394059


* Fri Mar 24 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-106
- Add 0212-RHBZ-1431562-for-read-only.patch
- Resolves: bz #1431562

* Fri Mar 10 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-105
- fix specfile issue
- Related: bz #1430097

* Thu Mar  9 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-104
- Change _pkgconfdir from /usr/share/pkgconfig to /usr/lib/pkgconfig
- Modify 0209-UPBZ-1430097-multipath-C-API.patch
  * change _pkgconfdir and fixed double-closing fd
- Add 0211-RH-strlen-fix.patch
  * checks that variables are not NULL before passing them to strlen
- Related: bz #1430097

* Thu Mar  9 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-103
- Add more explicit Requires to subpackages to make rpmdiff happy
- Related: bz #1430097

* Tue Mar  7 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-102
- Add 0207-UP-add-libmpathcmd.patch
  * New shared library, libmpathcmd, that sends and receives messages from
    multipathd. device-mapper-multipath now uses this library internally.
- Add 0208-UPBZ-1430097-multipathd-IPC-changes.patch
  * validation that modifying commands are coming from root.
- Add 0209-UPBZ-1430097-multipath-C-API.patch
  * New shared library. libdmmp, that presents the information from multipathd
    in a structured manner to make it easier for callers to use
- Add 0210-RH-fix-uninstall.patch
  * Minor compilation fixes
- Make 3 new subpackages
  * device-mapper-multipath-devel, libdmmp, and libdmmp-devel. libmpathcmd
    and libmpathprio are in device-mapper-multipath-libs and
    device-mapper-multipath-devel. libdmmp is in its own subpackages
- Move libmpathprio devel files to device-mapper-multipath-devel
- Resolves: bz #1430097

* Wed Feb 15 2017 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-101
- Modify 0166-RHBZ-1323429-dont-allow-new-wwid.patch
  * change print message
- Add 0191-RHBZ-1169168-disable-changed-paths.patch
  * add "disabled_changed_wwids" multipath.conf parameter to disable
    paths whose wwid changes
- Add 0192-RHBZ-1362409-infinibox-config.patch
- Add 0194-RHBZ-1351964-kpartx-recurse.patch
  * fix recursion on corrupt dos partitions
- Add 0195-RHBZ-1359510-no-daemon-msg.patch
  * print a messages when multipathd isn't running
- Add 0196-RHBZ-1239173-dont-set-flag.patch
  * don't set reload flag on reloads when you gain your first
    valid path
- Add 0197-RHBZ-1394059-max-sectors-kb.patch
  * add "max_sectors_kb" multipath.conf parameter to set max_sectors_kb
    on a multipath device and all its path devices
- Add 0198-RHBZ-1372032-detect-path-checker.patch
  * add "detect_checker" multipath.conf parameter to detect ALUA arrays
    and set the path checker to TUR
- Add 0199-RHBZ-1279355-3pardata-config.patch
- Add 0200-RHBZ-1402092-orphan-status.patch
  * clear status on orphan paths
- Add 0201-RHBZ-1403552-silence-warning.patch
- Add 0202-RHBZ-1362120-skip-prio.patch
  * don't run prio on failed paths
- Add 0203-RHBZ-1363718-add-msgs.patch
- Add 0204-RHBZ-1406226-nimble-config.patch
- Add 0205-RHBZ-1416569-reset-stats.patch
  * add "reset maps stats" and "reset map <map> stats" multipathd
    interactive commands to reset the stats tracked by multipathd
- Add 0206-RHBZ-1239173-pt2-no-paths.patch
  * make multipath correctly disable scanning and rules running when
    it gets a uevent and there are not valid paths.
- Resolves: bz #1169168, #1239173, #1279355, #1359510, #1362120, #1362409
- Resolves: bz #1363718, #1394059, #1351964, #1372032, #1402092, #1403552
- Resolves: bz #1406226, #1416569

* Wed Sep  7 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-100
- Add 0189-RHBZ-1368211-remove-retries.patch
  * add "remove_retries" multipath.conf parameter to make multiple attempts
    to remove a multipath device if it is busy.
- Add 0190-RHBZ-1380602-rbd-lock-on-read.patch
  * pass lock_on_read when remapping image
- Resolves: bz #1368211, #1380602

* Wed Sep  7 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-99
- Add 0188-RHBZ-1368501-dont-exit.patch
  * make multipathd not exit if it encounters recoverable errors on startup
- Resolves: bz #1368501

* Thu Sep  1 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-98
- Modified 0180-multipath-tools-Add-rbd-checker.patch
  * make the rbd path checker only compile if librados2-devel is installed
- Make librados2-devel only be BuildRequired on x86_64
- Resolves: bz #1348372

* Thu Sep  1 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-97
- Add 0177-libmultipath-correctly-initialize-pp-sg_id.patch
  * This and all the following patches add the rbd patch checker
- Add 0178-libmultipath-add-rbd-discovery.patch
- Add 0179-multipath-tools-add-checker-callout-to-repair-path.patch
- Add 0180-multipath-tools-Add-rbd-checker.patch
- Add 0181-multipath-tools-Add-rbd-to-the-hwtable.patch
- Add 0182-multipath-tools-check-for-initialized-checker-before.patch
- Add 0183-multipathd-Don-t-call-repair-on-blacklisted-path.patch
- Add 0184-rbd-fix-sync-repair-support.patch
- Add 0185-rbd-check-for-nonshared-clients.patch
- Add 0186-rbd-check-for-exclusive-lock-enabled.patch
- Add 0187-rbd-fixup-log-messages.patch
- Added BuildRequires on librados2-devel
- Resolves: bz #1348372


* Mon Aug  8 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-96
- Modify 0136-RHBZ-1304687-wait-for-map-add.patch
  * change missing_uev_msg_delay to missing_uev_msg_timeout, and make
    multipathd re-enable table loads if the timeout has passed
- Refresh 0137-RHBZ-1280524-clear-chkr-msg.patch
- Refresh 0139-RHBZ-1273173-queue-no-daemon-doc.patch
- Refresh 0150-RHBZ-1253913-fix-startup-msg.patch
- Refresh 0154-UPBZ-1291406-disable-reinstate.patch
- Refresh 0155-UPBZ-1300415-PURE-config.patch
- Refresh 0156-UPBZ-1313324-dont-fail-discovery.patch
- Refresh 0161-RHBZ-1311659-no-kpartx.patch
- Refresh 0167-RHBZ-1335176-fix-show-cmds.patch
- Add 0173-RH-update-man-page.patch
- Add 0174-RHBZ-1362396-modprobe.patch
  * make starting the multipathd service modprobe dm-multipath in the
    sysvinit scripts
- Add 0175-RHBZ-1357382-ordering.patch
  * force multipathd.service to start after systemd-udev-trigger.service
- Add 0176-RHBZ-1363830-fix-rename.patch
  * initialized a variable to make dm_rename not fail randomly
- Resolves: bz #1304687, #1362396, #1357382, #1363830

* Wed Jul 20 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-95
- Add 0170-UPBZ-1352925-fix-typo.patch
- Add 0171-UPBZ-1356651-allow-zero-size.patch
  * Allow zero-sized paths to be added to a multipath device
- Add 0172-RHBZ-1350931-no-active-add.patch
  * Allow paths to be added to a new map if no active paths exist. Also
    fixes 1351430
- Resolves: bz #1350931, #1351430, #1352925, #1356651


* Mon Jul 18 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-94
- Modify 0169-UPBZ-1353357-json-output.patch
  * Add manpage documentation
- Resolves: bz #1353357

* Fri Jul 15 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-93
- Modify 0135-RHBZ-1299600-path-dev-uevents.patch
  * trigger uevents when adding wwids for existing devices during startup
- Refresh 0136-RHBZ-1304687-wait-for-map-add.patch
- Refresh 0150-RHBZ-1253913-fix-startup-msg.patch
- Add 0168-RHBZ-1347769-shared-lock.patch
  * make multipath lock the path devices with a shared lock
- Add 0169-UPBZ-1353357-json-output.patch
  * add mulitpathd json output command
- Resolves: bz #1299600, #1347769, #1353357

* Tue Jul  5 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-92
- Add 0166-RHBZ-1323429-dont-allow-new-wwid.patch
  * don't allow path wwid to change while it is in use
- Add 0167-RHBZ-1335176-fix-show-cmds.patch
  * and new show multipath format wildcard, 'f' to sho number of failures.
    This will hopefully be useful for tracking what happens to multipath
    devices for bz #1335176
- Resolves: bz #1323429

* Thu Jun  2 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-91
- Add 0165-UPBZ-1341748-MSA-2040-conf.patch
  * Add default config for MSA 2040 array
- Resolves: bz #1341748

* Wed Jun  1 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-90
- Modify 0159-UPBZ-1255885-udev-waits.patch
  * fix bug in failure path
- Add 0160-RH-udev-flags.patch
- Add 0161-RHBZ-1311659-no-kpartx.patch
  * skip_kpartx option disables kpartx running on multipath devices
- Add 0162-RHBZ-1333331-huawei-config.patch
  * Add default config for Huawei XSG1 array
- Add 0163-UPBZ-1333492-resize-map.patch
  * restore old size if resize fails
- Add 0164-RHBZ-1311463-dos-part-rollover.patch
  * fix incorrect partition size due to 4k device size rollover
- Resolves: bz #1255885, #1311463, #1311659, #1333331, #1333492

* Wed Apr 20 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-89
- Modify 0151-RHBZ-1297456-weighted-fix.patch
  * add documentation
- Add 0157-RHBZ-1319853-multipath-c-error-msg.patch
  * better error reporting for multipath -c
- Add 0158-RHBZ-1318581-timestamp-doc-fix.patch
  * add documentation for -T
- Add 0159-UPBZ-1255885-udev-waits.patch
  * make multipath and kpartx wait after for udev after each command
- Resolves: bz #1297456, #1319853, #1318581, #1255885

* Tue Mar 29 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-88
- Add 0151-RHBZ-1297456-weighted-fix.patch
  * add wwn keyword to weighted prioritizer for persistent naming
- Add 0152-RHBZ-1269293-fix-blk-unit-file.patch
  * use "Wants" instead of "Requires"
- Add 0153-RH-fix-i686-size-bug.patch
  * use 64-bit keycodes for multipathd client commands
- Add 0154-UPBZ-1291406-disable-reinstate.patch
  * don't automatically reinstate ghost paths for implicit alua devices
- Add 0155-UPBZ-1300415-PURE-config.patch
  * Add default config for PURE FlashArray
- Add 0156-UPBZ-1313324-dont-fail-discovery.patch
  * don't fail discovery because individual paths failed.
- Resolves: bz #1297456, #1269293, #1291406, #1300415, #1313324

* Fri Feb 26 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-87
- Add 0133-RHBZ-1241774-sun-partition-numbering.patch
  * makr kpartx device numbers match partition numbers
- Add 0134-RHBZ-1241528-check-mpath-prefix.patch
  * only touch devices with a "mpath-" dm uuid prefix
- Add 0135-RHBZ-1299600-path-dev-uevents.patch
  * trigger path uevent the first time a path is claimed by multipath
- Add 0136-RHBZ-1304687-wait-for-map-add.patch
  * wait for the device to finish being added before reloading it.
- Add 0137-RHBZ-1280524-clear-chkr-msg.patch
- Add 0138-RHBZ-1288660-fix-mpathconf-allow.patch
  * don't remove existing lines from blacklist_exceptions section
- Add 0139-RHBZ-1273173-queue-no-daemon-doc.patch
- Add 0140-RHBZ-1299647-fix-help.patch
- Add 0141-RHBZ-1303953-mpathpersist-typo.patch
- Add 0142-RHBZ-1283750-kpartx-fix.patch
  * only remove devices if their uuid says that they are the correct
    partition device
- Add 0143-RHBZ-1299648-kpartx-sync.patch
  * default to using udev sync mode
- Add 0144-RHBZ-1299652-alua-pref-arg.patch
  * allow "exclusive_pref_bit" argument to alua prioritizer
- Add 0145-UP-resize-help-msg.patch
- Add 0146-UPBZ-1299651-raw-output.patch
  * allow raw format mutipathd show commands, that remove headers and padding
- Add 0147-RHBZ-1272620-fail-rm-msg.patch
- Add 0148-RHBZ-1292599-verify-before-remove.patch
  * verify that all partitions are unused before attempting to remove a device
- Add 0149-RHBZ-1292599-restore-removed-parts.patch
  * don't disable kpartx when restoring the first path of a device.
- Add 0150-RHBZ-1253913-fix-startup-msg.patch
  * wait for multipathd daemon to write pidfile before returning
- Resolves: bz #1241528, #1241774, #1253913, #1272620, #1273173, #1280524
- Resolves: bz #1283750, #1288660, #1292599, #1299600, #1299647, #1299648
- Resolves: bz #1299651, #1299652, #1303953, #1304687

* Wed Jan 27 2016 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-86
- Add 0132-RHBZ-1296979-fix-define.patch
  * look for the correct libudev function to set define
- Resolves: bz # 1296979

* Thu Sep 17 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-85
- Fix device-mapper Requires line in spec file
- Resolves: bz# 1260728

* Mon Sep 14 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-84
- 0131-UPBZ-1259831-lock-retry.patch
  * retry locking when creating multipath devices
- Resolves: bz# 1259831

* Tue Sep  8 2015 Benjmain Marzinski <bmarzins@redhat.com> 0.4.9-83
- Add 0130-RHBZ-1259523-host_name_len.patch
  * increase size of host string
- Resolves: bz# 1259523

* Wed Aug 19 2015 Benjmain Marzinski <bmarzins@redhat.com> 0.4.9-82
- Add 0129-UPBZ-1254292-iscsi-targetname.patch
  * check for targetname iscsi sysfs value
- Resolves: bz #1254292

* Wed Jul  8 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-81
- Modify 0128-RHBZ-1222123-mpathconf-allow.patch
  * Fix up covscan complaints.
- Related: bz #1222123

* Tue Jul  7 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-80
- Add 0127-RHBZ-1201030-use-blk-availability.patch
  * Make multipath use blk-availability.service
- Add 0128-RHBZ-1222123-mpathconf-allow.patch
  * Add mpathconf --allow for creating specialized config files.
- Resolves: bz #1201030, #1222123

* Fri Jun  5 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-79
- Add 0124-RHBZ-1209275-retrigger-uevents.patch
  * Make multipathd retrigger uevents when paths haven't successfully had
    their udev_attribute environment variable set by udev and add
    "retrigger_ties" and "retrigger_delay" to control this
- Add 0125-RHBZ-1153832-kpartx-delete.patch
  * Delete all partition devices with -d (not just the ones in the partition
    table)
- Add 0126-RHBZ-1211383-alias-collision.patch
  * make multipathd use the old alias, if rename failed and add
    "new_bindings_in_boot" to determine if new bindings can be added to
    the bindings file in the initramfs
- Resolves: bz #1153832, #1209275, #1211383

* Thu May  7 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-78
- Modify 0102-RHBZ-631009-deferred-remove.patch
  * Code refactor and minor fix.
- Add 0106-RHBZ-1169935-no-new-devs.patch
  * add new configuration option "ignore_new_boot_devs"
- Add 0107-RH-adapter-name-wildcard.patch
  * add new paths wildcard to show the host adapter
- Add 0108-RHBZ-1153832-kpartx-remove-devs.patch
  * switch to kpartx -u in 62-multipath.rules to delete removed partitions
- Add 0109-RH-read-only-bindings.patch
  * add -B support to multipathd
- Add 0110-RHBZ-blacklist-vd-devs.patch
  * virtio-blk devices don't report a WWID so multipath can't use them
- Add 0111-RH-dont-show-pg-timeout.patch
  * remove pg_timeout setting and displaying code
- Add 0112-RHBZ-1194917-add-config_dir-option.patch
  * add new configuration option "config_dir"
- Add 0113-RHBZ-1194917-cleanup.patch
  * code refactoring
- Add 0114-RHBZ-1196394-delayed-reintegration.patch
  * add new configuration options "delay_watch_checks" and
    "delay_wait_checks"
- Add 0115-RHBZ-1198418-fix-double-free.patch
  * fix crash when multipath fails adding a multipath device
- Add 0116-UPBZ-1188179-dell-36xxi.patch
  * New builtin config
- Add 0117-RHBZ-1198424-autodetect-clariion-alua.patch
  * update default config
- Add 0118-UPBZ-1200738-update-eternus-config.patch
  * update default config
- Add 0119-RHBZ-1081397-save-alua-info.patch
  * make prioritizers save information between calls to speed them up.
- Add 0120-RHBZ-1043093-realloc-fix.patch
  * free old memory if realloc fails.
- Add 0121-RHBZ-1197234-rules-fix.patch
  * make sure kpartx runs after an DM_ACTIVATION event occurs.
- Add 0122-RHBZ-1212590-dont-use-var.patch
  * use /run instead of /var/run
- Add 0123-UPBZ-1166072-fix-path-offline.patch
  * Don't mark quiesce and transport-offline paths as offline
- Modify mulfipth.conf default config file (bz #1194794)
- Related: bz #1153832
- Resolves: bz #631009, #1043093, #1081397, #1166072, #1169935, #1188179
- Resolves: bz #1194794, #1194917, #1196394, #1197234, #1198418, #1198424
- Resolves: bz #1200738, #1212590

* Fri Jan  9 2015 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-77
- Add 0105-RHBZ-1180032-find-multipaths-man.patch
  * add find_multipaths to man page
- Modify multipath.conf (bz #1069360)
  * add uid_attribute example
- Resolves: bz #1180032

* Fri Nov 14 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-76
- Modify 0102-RHBZ-631009-deferred-remove.patch
  * Fixed compiler warning message for builds with old device-mapper versions
- Add 0104-RHBZ-1159337-fix-double-free.patch
  * made ev_remove_path exit immediately after failing setup_multipath, since
    it handles cleaning up the device
- Resolves: bz #1159337
- Related: bz #631009

* Thu Nov  6 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-75
- Add 0103-RHBZ-1148979-fix-partition-mapping-creation-race-with-kpartx.patch
  * Only run kpartx on device activation
- Resolves: bz #1148979

* Tue Oct 28 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-74
- Respin again to let buildroot catch up.
- Related: bz #631009

* Tue Oct 28 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-73
- Respin to pick up latest lvm2 code
- Related: bz #631009

* Tue Oct 28 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-72
- Add 0101-RH-cleanup-partmaps-code.patch
  * code refactoring to prepare for next patch
- Add 0102-RHBZ-631009-deferred-remove.patch
  * add deferred_remove option to /etc/multipath.conf
- Resolves: bz #631009

* Fri Sep  5 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-71
- Re-add 0050-RH-listing-speedup.patch
- Modify 0098-UPBZ-1067171-mutipath-i.patch
  * add dry_run cleanup code from upstream
- Refresh 0099-RH-add-all-devs.patch
- Add 0100-RHBZ-1067171-multipath-i-update.patch
  * make -i work correctly with find_multipaths
- Resolves: bz #1067171

* Wed Sep  3 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-70
- Modify 0096-RHBZ-979474-new-wildcards.patch
  * Fix a faulty check
- Add 0098-UPBZ-1067171-mutipath-i.patch
  * Add -i option to ignore wwids file when checking for valid paths
- Add 0099-RH-add-all-devs.patch
  * Add new devices config option all_devs. This makes the configuration
    overwrite the specified values in all builtin configs
- Related: bz #979474
- Resolves: bz #1067171

* Thu Aug 28 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-69
- Add 0096-RHBZ-979474-new-wildcards.patch
  * Add N, n, R, and r path wildcards to print World Wide ids
- Add 0097-RH-fix-coverity-errors.patch
  * Fix a number of unterminated strings and memory leaks on failure
    paths.
- Resolves: bz #979474

* Tue Aug 12 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-68
- Add 0091-RHBZ-1069584-fix-empty-values-fast-io-fail-and-dev-loss.patch
  * check for null pointers in configuration reading code.
- Add 0092-UPBZ-1104605-reload-on-rename.patch
  * Reload table on rename if necessary
- Add 0093-UPBZ-1086825-user-friendly-name-remap.patch
  * Keep existing user_friend_name if possible
- Add 0094-RHBZ-1086825-cleanup-remap.patch
  * Cleanup issues with upstream patch
- Add 0095-RHBZ-1127944-xtremIO-config.patch
  * Add support for EMC ExtremIO devices
- Resolves: bz #1069584, #1104605, #1086825, #1086825, #1127944

* Tue Aug 12 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-67
- Modify multipath.conf (bz #1069360)
  * remove getuid_callout example
- Add 0081-RHBZ-1066264-check-prefix-on-rename.patch
  * make multipath check the prefix on kpartx partitions during rename, and
    copy the existing behaviour
- Add 0082-UPBZ-1109995-no-sync-turs-on-pthread_cancel.patch
  * If async tur checker fails on threads, don't retry with the sync version
- Add 0083-RHBZ-1080055-orphan-paths-on-reload.patch
  * Fix case where pathlist wasn't getting updated properly
- Add 0084-RHBZ-1110000-multipath-man.patch
  * fix errors in multipath man page
- Add 0085-UPBZ-1110006-datacore-config.patch
  * Add support for DataCore Virtual Disk
- Add 0086-RHBZ-1110007-orphan-path-on-failed-add.patch
  * If multipathd fails to add path correctly, it now fully orphans the path
- Add 0087-RHBZ-1110013-config-error-checking.patch
  * Improve multipath.conf error checking.
- Add 0088-RHBZ-1069811-configurable-prio-timeout.patch
  * checker_timeout now adjusts the timeouts of the prioritizers as well.
- Add 0089-RHBZ-1110016-add-noasync-option.patch
  * Add a new defaults option, "force_sync", that disables the async mode
    of the path checkers. This is for cases where to many parallel checkers
    hog the CPU
- Add 0090-UPBZ-1080038-reorder-paths-for-round-robin.patch
  * make multipathd order paths for better throughput in round-robin mode
- Resolves: bz #1069360, #1066264, #1109995, #1080055, #1110000, #1110006
- Resolves: bz #1110007, #1110013, #1069811, #1110016, #1080038

* Wed Mar 12 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-66
- Add 0080-RHBZ-1075796-cmdline-wwid.patch
  * add multipath option "-A" to add wwids specified by the kernel
    command line mapth.wwid options.
- Resolves: bz #1075796

* Mon Mar  3 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-65
- Add 0078-RHBZ-1054044-fix-mpathconf-manpage.patch
  * Fix typo
- Add 0079-RHBZ-1070581-add-wwid-option.patch
  * add multipath option "-a". To add a device's wwid to the wwids file
- Resolves: bz #1054044, #1070581

* Thu Jan 30 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-64
- Modify 0076-RHBZ-1056686-add-hw_str_match.patch
  * Fix memory leak
- Resolves: bz #1056686

* Wed Jan 29 2014 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-63
- Modify 0072-RHBZ-1039199-check-loop-control.patch
  * only call close on the /dev/loop-control fd the open succeeds
- Add 0073-RH-update-build-flags.patch
  * fix print call to work with -Werror=format-security compile flag, and
    change compilation flags for non-rpmbuild compiles
- Add 0074-RHBZ-1056976-dm-mpath-rules.patch
  * Add rules to keep from doing work in udev if there are no
    active paths, or if the event was for a multipath device
    reloading its table due to a path change.
- Add 0075-RHBZ-1056976-reload-flag.patch
  * multipath code to identify reloads that the new rules can
    ignore
- Add 0076-RHBZ-1056686-add-hw_str_match.patch
  * add a new default config paramter, "hw_str_match", to make user
    device configs only overwrite builtin device configs if the
    identifier strings match exactly, like the default in RHEL6.
- Add 0077-RHBZ-1054806-mpathconf-always-reload.patch
  * Make mpathconf always reconfgure multipathd when you run it with
    a reconfigure option and --with-multipathd=y, even if the
    configuration doesn't change.
- Update Requires and BuildRequires for device-mapper to 1.02.82-2
- Install new udev rules file /usr/lib/udev/rules.d/11-dm-mpath.rules
- Related: bz #1039199
- Resolves: bz #1054806, #1056686, #1056976

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 0.4.9-62
- Mass rebuild 2014-01-24

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 0.4.9-61
- Mass rebuild 2013-12-27

* Wed Dec 11 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-60
- Add 0072-RHBZ-1039199-check-loop-control.patch
  * Make kpartx use LOOP_CTL_GET_FREE and loop-control to find a free
    loop device. This will autoload the loop module.
- Resolves: bz #1039199

* Mon Dec  9 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-59
- Add 0067-RHBZ-1022899-fix-udev-partition-handling.patch
  * Make sure to wipe partition devices on change event if they weren't
    wiped on the device add event
- Add 0068-RHBZ-1034578-label-partition-devices.patch
  * Make sure that partition devices are labeled like the whole device
- Add 0069-UPBZ-1033791-improve-rdac-checker.patch
  *  Use RTPG data in RDAC checker
- Add 0070-RHBZ-1036503-blacklist-td-devs.patch
- Add 0071-RHBZ-1031546-strip-dev.patch
  * make multipathd interactive commands able to handle /dev/<devnode>
    instead of just <devnode>
- Resolves: bz #1022899, #1031546, #1033791, #1034578, #1036503

* Thu Oct 24 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-58
- 0066-UP-dos-4k-partition-fix.patch
  * Make kpartx correctly handle 4K sector size devices with dos partitions.
- Resolves: bz #1018439

* Fri Sep 27 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-57
- Add 0065-UPBZ-995538-fail-rdac-on-unavailable.patch
  * make rdac checker always mark paths with asymmetric access state of
    unavailable as down
- Resolves: bz #995538

* Wed Sep 25 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-56
- Add 0064-RHBZ-1010040-fix-ID_FS-attrs.patch
  * make multipath create a timestamp file /run/multipathd/timestamp, and
    add -T<timestamp>:<valid> option to shortcut processing if the
    timestamp hasn't changed
- Resolves: bz #1010040

* Fri Sep  6 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-55
- Add 0061-RH-display-find-mpaths.patch
- Add 0062-RH-dont-free-vecs.patch
  * freeing vecs causes a number of races which can crash multipathd on
    shutdown.
- Add 0063-RH-fix-warning.patch

* Thu Jul 25 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-54
- Modify 0015-RH-fix-output-buffer.patch
  * Fix memory leak
- Add 0047-RHBZ-kpartx-read-only-loop-devs.patch
  * Fix read only loop device handling
- Add 0048-RH-print-defaults.patch
- Add 0049-RH-remove-ID_FS_TYPE.patch
  * remove ID_FS_TYPE udev enviroment variable for multipath devices
- Add 0051-UP-fix-cli-resize.patch
  * check before dereferencing variables
- Add 0052-RH-fix-bad-derefs.patch
  * setup multipath free the multipath device when it fails, so don't keep
    using it.
- Add 0053-UP-fix-failback.patch
  * setting failback in the devices section was broken
- Add 0054-UP-keep-udev-ref.patch
  * multipathd needs to keep the same udev object across reconfigures
- Add 0055-UP-handle-quiesced-paths.patch
  * quiesced paths should be treated as down
- Add 0056-UP-alua-prio-fix.patch
  * Don't count the preferred bit for paths that are active/optimized
- Add 0057-UP-fix-tmo.patch
  * Cleanup how multipath sets dev_loss_tmo and fast_io_fail_tmo.  Also
    make multipath get changing values directly from sysfs, instead of
    from udev, which caches them.
- Add 0058-UP-fix-failback.patch
  * make failback print the default value when you show configs.
- Add 0059-UP-flush-failure-queueing.patch
  * If you can't flush a multipath device, restore the queue_if_no_paths
    value
- Add 0060-UP-uevent-loop-udev.patch
  * make ueventloop grab it's own udev reference, since it is cancelled
    asychnrously.

* Wed Jul  3 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-53
- Add 0044-RHBZ-976688-fix-wipe-wwids.patch
  * Seek back to the start of the file after truncating it
- Add 0045-RHBZ-977297-man-page-fix.patch
  * update man page to match actual defaults
- Add 0046-RHBZ-883981-move-udev-rules.patch
  * move udev rules file from /lib to /usr/lib
- Resolves: bz #883981, #976688, #977297

* Fri Jun 21 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-52
- Add 0038-RHBZ-799860-netapp-config.patch
- Add 0039-RH-detect-prio-fix.patch
  * Don't autodetect ALUA prioritizer unless it actually can get a priority
- Add 0040-RH-bindings-fix.patch
  * Do a better job of trying to get the first free user_friendly_name
- Add 0041-RH-check-for-erofs.patch
  * Don't create/reload a device read-only unless doing it read/write fails
    with EROFS
- Remove 0017-RH-fix-sigusr1.patch
  * fix signal handling upstream way instead
- Add 0042-UP-fix-signal-handling.patch
  * uxlsnr now handles all the signals sent to multipathd. This makes its
    signal handling posix compliant, and harder to mess up.
- Add 0043-RH-signal-waiter.patch
  * ioctl isn't a pthread cancellation point.  Send a signal to the waiter
    thread to break out of waiting in ioctl for a dm event.

* Fri May 17 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-51
- Add 0032-RHBZ-956464-mpathconf-defaults.patch
  * fix defaults listed in usage
- Add 0033-RHBZ-829963-e-series-conf.patch
- Add 0034-RHBZ-851416-mpathconf-display.patch
  * display whether or not multipathd is running in the status
- Add 0035-RHBZ-891921-list-mpp.patch
  * add a new path format wilcard to list the multipath device associated
    with a path
- Add 0036-RHBZ-949239-load-multipath-module.patch
  * load the dm-multipath kernel module when multipathd starts
- Add 0037-RHBZ-768873-fix-rename.patch
  * When deciding on a multipth devices name on reload, don't default to
    the existing name if there is no config file alias and user_friendly_names
    isn't set. Use the wwid.
- Modify multipath.conf
- Resolves: bz #768873, #950252

* Tue Apr 30 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-50
- Add 0031-RHBZ-957188-kpartx-use-dm-name.patch
  * use the basename of the devices that will be created to choose the
    delimiter instead of using the device name from the command line
- Resolves: bz #957188

* Fri Apr 26 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-49
- Modify 0020-RHBZ-907360-static-pthread-init.patch
  * Don't initialize uevent list twice
- Add 0029-RH-no-prio-put-msg.patch
- Add 0030-RHBZ-916528-override-queue-no-daemon.patch
  * Default to "queue_without_daemon no"
  * Add "forcequeueing daemon" and "restorequeueing daemon" cli commands
- Modify spec file to force queue_without_daemon when restarting
  multipathd on upgrades.

* Thu Apr  4 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-48
- Add 0026-fix-checker-time.patch
  * Once multipathd hit it max checker interval, it was reverting to
    to shortest checker interval
- Add 0027-RH-get-wwid.patch
  * Multipath wasn't correctly setting the multipath wwid when it read devices
    in from the kernel
- Add 0028-RHBZ-929078-refresh-udev-dev.patch
  * Make multipath try to get the UID of down devices.  Also, on ev_add_path,
    make multipathd reinitialize existing devices that weren't fully
    initialized before.

* Mon Apr  1 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-47
- Add 0021-RHBZ-919119-respect-kernel-cmdline.patch
  * keep the multipath.rules udev file from running and multipathd from
    starting if nompath is on the kernel command line
- Add 0022-RH-multipathd-check-wwids.patch
  * Whenever multipath runs configure, it will check the wwids, and
    add any missing ones to the wwids file
- Add 0023-RH-multipath-wipe-wwid.patch
  * multipath's -w command will remove a wwid from the wwids file
- Add 0024-RH-multipath-wipe-wwids.patch
  * multipath's -W command will set reset the wwids file to just the current
    devices
- Add 0025-UPBZ-916668_add_maj_min.patch
- Resolves: bz #919119

* Thu Mar 28 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-46
- Add 0020-RHBZ-907360-static-pthread-init.patch
  * statically initialize the uevent pthread structures

* Sat Mar  2 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-45
- Updated to latest upstrem 0.4.9 code: multipath-tools-130222
  (git commit id: 67b82ad6fe280caa1770025a6bb8110b633fa136)
- Refresh 0001-RH-dont_start_with_no_config.patch
- Modify 0002-RH-multipath.rules.patch
- Modify 0003-RH-Make-build-system-RH-Fedora-friendly.patch
- Refresh 0004-RH-multipathd-blacklist-all-by-default.patch
- Refresh 0005-RH-add-mpathconf.patch
- Refresh 0006-RH-add-find-multipaths.patch
- Add 0008-RH-revert-partition-changes.patch
- Rename 0008-RH-RHEL5-style-partitions.patch to
     0009-RH-RHEL5-style-partitions.patch
- Rename 0009-RH-dont-remove-map-on-enomem.patch to
     0010-RH-dont-remove-map-on-enomem.patch
- Rename 0010-RH-deprecate-uid-gid-mode.patch to
     0011-RH-deprecate-uid-gid-mode.patch
- Rename 0013-RH-kpartx-msg.patch to 0012-RH-kpartx-msg.patch
- Rename 0035-RHBZ-883981-cleanup-rpmdiff-issues.patch to
         0013-RHBZ-883981-cleanup-rpmdiff-issues.patch
- Rename 0039-RH-handle-other-sector-sizes.patch to
     0014-RH-handle-other-sector-sizes.patch
- Rename 0040-RH-fix-output-buffer.patch to 0015-RH-fix-output-buffer.patch
- Add 0016-RH-dont-print-ghost-messages.patch
- Add 0017-RH-fix-sigusr1.patch
  * Actually this fixes a number of issues related to signals
- Rename 0018-RH-remove-config-dups.patch to 0018-RH-fix-factorize.patch
  * just the part that isn't upstream
- Add 0019-RH-fix-sockets.patch
  * makes abstract multipathd a cli sockets use the correct name.
- Set find_multipaths in the default config

* Wed Feb 20 2013 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-44
- Add 0036-UP-fix-state-handling.patch
  * handle transport-offline and quiesce sysfs state
- Add 0037-UP-fix-params-size.patch
- Add 0038-RH-fix-multipath.rules.patch
  * make sure multipath's link priority gets increased
- Add 0039-RH-handle-other-sector-sizes.patch
  * allow gpt partitions on 4k sector size block devices.
- Add 0040-RH-fix-output-buffer.patch
  * fix multipath -ll for large configuration.

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.9-43
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Fri Dec 21 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-42
- Add 0034-RHBZ-887737-check-for-null-key.patch
- Add 0035-RHBZ-883981-cleanup-rpmdiff-issues.patch
  * Compile multipathd with full RELRO and PIE and install to /usr

* Mon Dec 17 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-41
- Add 0033-RH-dont-disable-libdm-failback-for-sync-case.patch
  * make kpartx -s and multipath use libdm failback device creation, so
    that they work in environments without udev

* Fri Nov 30 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-40
- Add 0032-RH-make-path-fd-readonly.patch
  * revert change made when adding persistent reservations, so that path fds
    are again opened O_RDONLY

* Fri Nov 30 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-39
- Add 0031-RHBZ-882060-fix-null-strncmp.patch

* Fri Nov 30 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-38
- Add 0026-RH-fix-mpathpersist-fns.patch
- Add 0027-RH-default-partition-delimiters.patch
  * Only use the -p delimiter when the device name ends in a number
- Add 0028-RH-storagetek-config.patch
- Add 0029-RH-kpartx-retry.patch
  * retry delete on busy loop devices
- Add 0030-RH-early-blacklist.patch
  * multipath will now blacklist devices by device type and wwid in
    store_pathinfo, so that it doesn't do a bunch of unnecessary work
    on paths that it would only be removing later on.

* Sat Nov 03 2012 Peter Rajnoha <prajnoha@redhat.com> 0.4.9-37
- Install multipathd.service for sysinit.target instead of multi-user.target.

* Thu Nov 01 2012 Peter Rajnoha <prajnoha@redhat.com> 0.4.9-36
- Start multipathd.service systemd unit before LVM units.

* Wed Oct 24 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-35
- Add 0022-RHBZ-864368-disable-libdm-failback.patch
  * make kpartx and multiapthd disable libdm failback device creation
- Add 0023-RHBZ-866291-update-documentation.patch
- Resolves: bz #864368, #866291

* Tue Oct 23 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-34
- Add 0021-RH-fix-oom-adj.patch
  * don't use OOM_ADJUST_MIN unless you're sure it's defined

* Tue Oct 23 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-33
- Modify 0016-RH-retain_hwhandler.patch
  * Check the dm-multipath module version, and don't enable
    retain_attached_hw_handler if the kernel doesn't support it
- Add 0019-RH-detect-prio.patch
  * add detect_prio option, to make multipath check if the device
    supports the ALUA prio, before defaulting to the configured prio
- Remove 0017-RH-netapp_config.patch
- Add 0020-RH-netapp-config.patch
  * new netapp config that uses retain_attached_hw_handler and
    detect_prio to autoconfigure ALUA and non-ALUA devices.

* Tue Oct  2 2012 Benjamin Marzinski <bmarizns@redhat.com> 0.4.9-32
- Modified 0018-RH-remove-config-dups.patch
  * Made modified config remove original only if the vendor/product
    exactly match

* Thu Sep 27 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-31
- Add 0014-RH-dm_reassign.patch
  * Fix reassign_maps option
- Add 0015-RH-selector_change.patch
  * devices default to using service-time selector
- Add 0016-RH-retain_hwhandler.patch
  * add retain_attached_hw_handler option, to let multipath keep an
    already attached scsi device handler
- Add 0017-RH-netapp_config.patch
- Add 0018-RH-remove-config-dups.patch
  * Clean up duplicates in the devices and blacklist sections

* Wed Sep 05 2012 Václav Pavlín <vpavlin@redhat.com> - 0.4.9-30
- Scriptlets replaced with new systemd macros (#850088)

* Tue Aug 21 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-29
- Updated to latest upstrem 0.4.9 code: multipath-tools-120821.tgz
  (git commit id: 050b24b33d3c60e29f7820d2fb75e84a9edde528)
  * includes 0001-RH-remove_callout.patch, 0002-RH-add-wwids-file.patch,
    0003-RH-add-followover.patch, 0004-RH-fix-cciss-names.patch
- Add 0013-RH-kpartx-msg.patch
- Modify 0002-RH-multipath.rules.patch
  * removed socket call from rules file

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.9-28
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Thu Jun 28 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-27
- Updated to latest upstream 0.4.9 code : multipath-tools-120613.tgz
  (git commit id: cb0f7127ba90ab5e8e71fc534a0a16cdbe96a88f)
- Add 0001-RH-remove_callout.patch
  * multipath no longer uses the getuid callout.  It now gets the
    wwid from the udev database or the environment variables
- Add 0004-RH-fix-cciss-names.patch
  * convert cciss device names from cciss/cXdY to sysfs style cciss!cXdY
- Split 0009-RH-add-find-multipaths.patch into 0002-RH-add-wwids-file.patch
        and 0010-RH-add-find-multipaths.patch
- Add 0016-RH-change-configs.patch
  * default fast_io_fail to 5 and don't set the path selector in the
    builtin configs.
Resolves: bz #831978


* Thu May 17 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-26
- Add 0025-RHBZ-822714-update-nodes.patch
- Resolves: bz #822714

* Mon Apr 30 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-25
- Modify 0024-RH-libudev-monitor.patch
- Resolves: bz #805493

* Mon Apr 30 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-24
- Add requirements on libudev to spec file
- Resolves: bz #805493

* Mon Apr 30 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-23
- Add 0024-RH-libudev-monitor.patch

* Fri Feb 10 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-22
- Add 0012-RH-update-on-show-topology.patch
- Add 0013-RH-manpage-update.patch
- Add 0014-RH-RHEL5-style-partitions.patch
- Add 0015-RH-add-followover.patch
- Add 0016-RH-dont-remove-map-on-enomem.patch
- Add 0017-RH-fix-shutdown-crash.patch
- Add 0018-RH-warn-on-bad-dev-loss-tmo.patch
- Add 0019-RH-deprecate-uid-gid-mode.patch
- Add 0020-RH-dont-remove-map-twice.patch
- Add 0021-RH-validate-guid-partitions.patch
- Add 0022-RH-adjust-messages.patch
- Add 0023-RH-manpage-update.patch

* Tue Jan 24 2012 Benjamin Marzinski <bmarzins@redhat.com> 0.4.9-21
- Updated to latest upstream 0.4.9 code : multipath-tools-120123.tgz
  (git commit id: 63704387009443bdb37d9deaaafa9ab121d45bfb)
- Add 0001-RH-fix-async-tur.patch
- Add 0002-RH-dont_start_with_no_config.patch
- Add 0003-RH-multipath.rules.patch
- Add 0004-RH-update-init-script.patch
- Add 0005-RH-cciss_id.patch
- Add 0006-RH-Make-build-system-RH-Fedora-friendly.patch
- Add 0007-RH-multipathd-blacklist-all-by-default.patch
- Add 0008-RH-add-mpathconf.patch
- Add 0009-RH-add-find-multipaths.patch
- Add 0010-RH-check-if-multipath-owns-path.patch
- Add 0011-RH-add-hp_tur-checker.patch

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.9-20
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Tue Sep 20 2011 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-19
- Modify 0103-add-disable-sync-option.patch
- Add 0104-RHBZ-737989-systemd-unit-fix.patch
  * systemd will only start multipathd if /etc/multipath.conf exists
- Add 0105-fix-oom-adj.patch
  * first try setting oom_score_adj

* Mon Aug 15 2011 Kalev Lember <kalevlember@gmail.com> - 0.4.9-18
- Rebuilt for rpm bug #728707

* Tue Jul 19 2011 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-17
- Add 0103-add-disable-sync-option.patch
  * add a -n (nosync) option to multipath. This disables synchronous
    file creation with udev.

* Fri Jul 15 2011 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-16
- Modify 0012-RH-udev-sync-support.patch
- Modify 0021-RHBZ-548874-add-find-multipaths.patch
- Modify 0022-RHBZ-557845-RHEL5-style-partitions.patch
- Add 0025-RHBZ-508827-update-multipathd-manpage.patch through
      0101-RHBZ-631009-disable-udev-disk-rules-on-reload.patch
  * sync with current state of RHEL6. Next release should include a updated
    source tarball with most of these fixes rolled in.
- Add 0102-RHBZ-690828-systemd-unit-file.patch
  * Add Jóhann B. Guðmundsson's unit file for systemd.
  * Add sub-package sysvinit for SysV init script.
- Resolves: bz #690828

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.9-15
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Feb 16 2010 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-14
- Modify 0021-RHBZ-548874-add-find-multipaths.patch
  * fix bug where mpathconf wouldn't create a multpath.conf file unless one
    already existed.

* Tue Feb 16 2010 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-13
- Replace 0012-RH-explicitly-disable-dm-udev-sync-support-in-kpartx.patch
  with 0012-RH-udev-sync-support.patch
  * Add udev sync support to kpartx and multipath. In kpartx it is disabled
    unless you use the -s option.
- Refresh 0013-RH-add-weighted_prio-prioritizer.patch
- Refresh 0021-RHBZ-548874-add-find-multipaths.patch
- Modify 0022-RHBZ-557845-RHEL5-style-partitions.patch
  * kpartx now creates a 2 sector large device for dos extended
    partitions, just like the kernel does on the regular block devices.
- Add 0023-RHBZ-557810-emc-invista-config.patch
- Add 0024-RHBZ-565933-checker-timeout.patch
  * Multipath has a new option checker_timeout. If this is not set,
    all path checker functions with explicit timeouts use
    /sys/block/sd<x>/device/timeout. If this is set, they use it instead.

* Fri Jan 22 2010 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-12
- Refresh 0001-RH-queue-without-daemon.patch
- Refresh 0002-RH-path-checker.patch
- Modify 0010-RH-multipath-rules-udev-changes.patch
  * Fix udev rules to use DM_SBIN_PATH when calling kpartx
  * install udev rules to /lib/udev/rules.d instead of /etc/udev/rules.d
- Modify 0014-RH-add-hp_tur-checker.patch
- Add 0003-for-upstream-default-configs.patch
- Add 0016-RHBZ-554561-fix-init-error-msg.patch
- Add 0017-RHBZ-554592-man-page-note.patch
- Add 0018-RHBZ-554596-SUN-6540-config.patch
- Add 0019-RHBZ-554598-fix-multipath-locking.patch
- Add 0020-RHBZ-554605-fix-manual-failover.patch
- Add 0021-RHBZ-548874-add-find-multipaths.patch
  * Added find_multipaths multipath.conf option
  * Added /sbin/mpathconf for simple editting of multipath.conf
- Add 0022-RHBZ-557845-RHEL5-style-partitions.patch
  * Make kpartx deal with logical partitions like it did in RHEL5.
    Don't create a dm-device for the extended partition itself.
    Create the logical partitions on top of the dm-device for the whole disk.

* Mon Nov 16 2009 Benjamin Marzinski <bmarzins@redhat.com> -0.4.9-11
- Add 0002-for-upstream-add-tmo-config-options.patch
  * Add fail_io_fail_tmo and dev_loss_tmo multipath.conf options
- Add 0013-RH-add-weighted_prio-prioritizer.patch
- Add 0014-RH-add-hp_tur-checker.patch
- Add 0015-RH-add-multipathd-count-paths-cmd.patch
- rename multipath.conf.redhat to multipath.conf, and remove the default
  blacklist.

* Tue Oct 27 2009 Fabio M. Di Nitto <fdinitto@redhat.com> - 0.4.9-10
- Updated to latest upstream 0.4.9 code : multipath-tools-091027.tar.gz
  (git commit id: a946bd4e2a529e5fba9c9547d03d3f91806618a3)
- Drop unrequired for-upstream patches.
- BuildRequires and Requires new device-mapper version for udev sync support.

* Tue Oct 20 2009 Fabio M. Di Nitto <fdinitto@redhat.com> - 0.4.9-9
- 0012-RH-explicitly-disable-dm-udev-sync-support-in-kpartx.patch

* Mon Oct 19 2009 Fabio M. Di Nitto <fdinitto@redhat.com> - 0.4.9-8
- Split patches in "for-upstream" and "RH" series.
- Replace 0011-RH-multipathd-blacklist-all-by-default.patch with
  version from Benjamin Marzinski.
- Update udev rules 0010-RH-multipath-rules-udev-changes.patch.
- rpmlint cleanup:
  * Drop useless-provides kpartx.
  * Cleanup tab vs spaces usage.
  * Summary not capitalized.
  * Missing docs in libs package.
  * Fix init script LSB headers.
- Drop README* files from doc sections (they are empty).

* Thu Oct 15 2009 Fabio M. Di Nitto <fdinitto@redhat.com> - 0.4.9-7
- Add patch 0010-RH-Set-friendly-defaults.patch:
  * set rcdir to fedora default.
  * do not install kpartx udev bits.
  * install redhat init script.
  * Cleanup spec file install target.
- Add patch 0011-RH-multipathd-blacklist-all-by-default.patch:
  * Fix BZ#528059
  * Stop installing default config in /etc and move it to the doc dir.

* Tue Oct 13 2009 Fabio M. Di Nitto <fdinitto@redhat.com> - 0.4.9-6
- Updated to latest upstream 0.4.9 code : multipath-tools-091013.tar.gz
  (git commit id: aa0a885e1f19359c41b63151bfcface38ccca176)
- Drop, now upstream, patches:
  * fix_missed_uevs.patch.
  * log_all_messages.patch.
  * uninstall.patch.
  * select_lib.patch.
  * directio_message_cleanup.patch.
  * stop_warnings.patch.
- Drop redhatification.patch in favour of spec file hacks.
- Drop mpath_wait.patch: no longer required.
- Merge multipath_rules.patch and udev_change.patch.
- Rename all patches based on source.
- Add patch 0009-RH-fix-hp-sw-hardware-table-entries.patch to fix
  default entry for hp_sw and match current kernel.
- Add multipath.conf.redhat as source instead of patch.
- spec file:
  * divide runtime and build/setup bits.
  * update BuildRoot.
  * update install section to apply all the little hacks here and there,
    in favour of patches against upstream.
  * move ldconfig invokation to libs package where it belong.
  * fix libs package directory ownership and files.

* Thu Aug 20 2009 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.9-5
- Fixed problem where maps were being added and then removed.
- Changed the udev rules to fix some issues.

* Thu Jul 30 2009 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.9-4
- Fixed build issue on i686 machines.

* Wed Jul 29 2009 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.9-3
- Updated to latest upstream 0.4.9 code : multipath-tools-090729.tgz
  (git commit id: d678c139719d5631194b50e49f16ca97162ecd0f)
- moved multipath bindings file from /var/lib/multipath to /etc/multipath
- Fixed 354961, 432520

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed May 6 2009 Mike Snitzer <snitzer@redhat.com> - 0.4.9-1
- Updated to latest upstream 0.4.9 code: multipath-tools-090429.tgz
  (git commit id: 7395bcda3a218df2eab1617df54628af0dc3456e)
- split the multipath libs out to a device-mapper-multipath-libs package
- if appropriate, install multipath libs in /lib64 and /lib64/multipath

* Tue Apr 7 2009 Milan Broz <mbroz@redhat.com> - 0.4.8-10
- Fix insecure permissions on multipathd.sock (CVE-2009-0115)

* Fri Mar 6 2009 Milan Broz <mbroz@redhat.com> - 0.4.8-9
- Fix kpartx extended partition handling (475283)

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.8-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Sep 26 2008 Benjamin Marzinski <bmarzins@redhat.com> 0.4.8-7
- Since libaio is now in /lib, not /usr/lib, multipath no longer needs to
  statically link against it. Fixed an error with binding file and WWIDs
  that include spaces. Cleaned up the messages from the directio checker
  function.  Fixed the udev rules. Fixed a regression in multipath.conf
  parsing
- Fixed 457530, 457589

* Wed Aug 20 2008 Benjamin Marzinski <bmarzins@redhat.com> 0.4.8-6
- Updated to latest upstream 0.4.8 code: multipath-tools-080804.tgz
  (git commit id: eb87cbd0df8adf61d1c74c025f7326d833350f78)
- fixed 451817, 456397 (scsi_id_change.patch), 457530 (config_space_fix.patch)
  457589 (static_libaio.patch)

* Fri Jun 13 2008 Alasdair Kergon <agk@redhat.com> - 0.4.8-5
- Rebuild (rogue vendor tag). (451292)

* Mon May 19 2008 Benjamin Marzinksi <bmarzins@redhat.com> 0.4.8-4
- Fixed Makefile issues.

* Mon May 19 2008 Benjamin Marzinksi <bmarzins@redhat.com> 0.4.8-3
- Fixed ownership build error.

* Mon May 19 2008 Benjamin Marzinksi <bmarzins@redhat.com> 0.4.8-2
- Forgot to commit some patches.

* Mon May 19 2008 Benjamin Marzinski <bmarzins@redhat.com> 0.4.8-1
- Updated to latest Upstream 0.4.8 code: multipath-tools-080519.tgz
  (git commit id: 42704728855376d2f7da2de1967d7bc71bc54a2f)

* Tue May 06 2008 Alasdair Kergon <agk@redhat.com> - 0.4.7-15
- Remove unnecessary multipath & kpartx static binaries. (bz 234928)

* Fri Feb 29 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 0.4.7-14
- fix sparc64
- fix license tag

* Tue Feb 19 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 0.4.7-13
- Autorebuild for GCC 4.3

* Wed Nov 14 2007 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.7-12
- Fixed the dist tag so building will work properly.

* Mon Feb 05 2007 Alasdair Kergon <agk@redhat.com> - 0.4.7-11.fc7
- Add build dependency on new device-mapper-devel package.
- Add dependency on device-mapper.

* Wed Jan 31 2007 Benjamin Marzinksi <bmarzins@redhat.com> - 0.4.7-10.fc7
- Update BuildRoot and PreReq lines.

* Mon Jan 15 2007 Benjamin Marzinksi <bmarzins@redhat.com> - 0.4.7-9.fc7
- Fixed spec file.

* Mon Jan 15 2007 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.7-8.fc7
- Update to latest code (t0_4_7_head2)

* Wed Dec 13 2006 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.7-7.fc7
- Update to latest code (t0_4_7_head1)

* Thu Sep  7 2006 Peter Jones <pjones@redhat.com> - 0.4.7-5
- Fix kpartx to handle with drives >2TB correctly.

* Thu Aug 31 2006 Peter Jones <pjones@redhat.com> - 0.4.7-4.1
- Split kpartx out into its own package so dmraid can use it without
  installing multipathd
- Fix a segfault in kpartx

* Mon Jul 17 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-4.0
- Updated to latest source. Fixes bug in default multipath.conf

* Wed Jul 12 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-3.1
- Added ncurses-devel to BuildRequires

* Wed Jul 12 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-3.0
- Updated to latest source. deals with change in libsysfs API

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 0.4.7-2.2.1
- rebuild

* Mon Jul 10 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-2.2
- fix tagging issue.

* Mon Jul 10 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-2.1
- changed BuildRequires from sysfsutils-devel to libsysfs-devel

* Wed Jun 28 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-2.0
- Updated to latest upstream source, fixes kpartx udev rule issue

* Tue Jun 06 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.7-1.0
- Updated to Christophe's latest source

* Mon May 22 2006 Alasdair Kergon <agk@redhat.com> - 0.4.5-16.0
- Newer upstream source (t0_4_5_post59).

* Mon May 22 2006 Alasdair Kergon <agk@redhat.com> - 0.4.5-12.3
- BuildRequires: libsepol-devel, readline-devel

* Mon Feb 27 2006 Benjamin Marzinski <bmarzins@redhat.com> 0.4.5-12.2
- Prereq: chkconfig

* Mon Feb 20 2006 Karsten Hopp <karsten@redhat.de> 0.4.5-12.1
- BuildRequires: libselinux-devel

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 0.4.5-12.0.1
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Benjamin Marzinski <bmarzins@redhat.com> -0.4.5-12.0
- Updated to latest upstream source (t0_4_5_post56)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 0.4.5-9.1.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Mon Dec 19 2005 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.5-9.1
- added patch for fedora changes

* Fri Dec 16 2005 Benjamin Marzinski <bmarzins@redhat.com> - 0.4.5-9.0
- Updated to latest upstream source (t)_4_5_post52)

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Sun Dec  4 2005 Peter Jones <pjones@redhat.com> - 0.4.4-2.6
- rebuild for newer libs

* Tue Nov 15 2005 Peter Jones <pjones@redhat.com> - 0.4.4-2.5
- unsplit kpartx.  parted knows how to do this now, so we don't
  need this in a separate package.

* Tue Nov 15 2005 Peter Jones <pjones@redhat.com> - 0.4.4-2.4
- split kpartx out into its own package

* Fri May 06 2005 Bill Nottingham <notting@redhat.com> - 0.4.4-2.3
- Fix last fix.

* Thu May 05 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-2.2
- Fix last fix.

* Wed May 04 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-2.1
- By default, disable the multipathd service.

* Tue Apr 19 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-2.0
- Fix core dump from last build.

* Tue Apr 19 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-1.0
- Move cache file into /var/cache/multipath.

* Fri Apr 08 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-0.pre8.1
- Remove pp_balance_units.

* Mon Apr 04 2005 Alasdair Kergon <agk@redhat.com> - 0.4.4-0.pre8.0
- Incorporate numerous upstream fixes.
- Update init script to distribution standards.

* Tue Mar 01 2005 Alasdair Kergon <agk@redhat.com> - 0.4.2-1.0
- Initial import based on Christophe Varoqui's spec file.
