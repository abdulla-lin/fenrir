from device import Device
from stage import PayloadStage, PatchStage
from patch_utils import MatchMode


DEVICES = [
    Device(
        'Pacman',
        'Nothing Phone 2a',
        {
            # Ideally, we'd make room in the 'lk' partition for the payload, but for the sake
            # of this demonstration, we take advantage of the fact that the BSP for this phone     
            # includes a lot of eMMC-related code that isn’t actually used, since this device 
            # uses UFS instead.                                                               
            #                                                                                 
            # Technically, these stages are not required by the exploit. They simply show    
            # that we can execute arbitrary code within the LK image, which is way cooler    
            # than just applying patches.                                                    
            #                                                                                 
            # The first address is the virtual base address where the stage payload is       
            # injected. The second address is the address of the `bl` call that we override  
            # to jump to the payload instead (called pivot by me, which is probably wrong).
            'stage1': PayloadStage(
                'stage1',
                0xFFFF000050F6F0A8,  # emmc_init()
                0xFFFF000050F05DA4,  # platform_init()
                description='Pre-platform initialization stage',
            ),
            'stage2': PayloadStage(
                'stage2',
                0xFFFF000050F6AE98, # msdc_tune_cmdrsp()
                0xFFFF000050F0E088, # bl notify_enter_fastboot()
                description='Pre-fastboot initialization stage',
            ),
            'stage3': PayloadStage(
                'stage3',
                0xFFFF000050F6C168, # msdc_config_bus()
                0xFFFF000050F0E0A4, # bl dprintf("%s:%d: Notify boot linux.\n")
                description='Linux initialization stage',
            ),

            # This is what makes it possible for this exploit to work. Long
            # story short, an LK image has various partitions inside it,
            # which each have a specific purpose and get loaded at a specific
            # address. The order matters, and each partition verifies the next
            # one before loading it.
            #
            # From my analysis, the boot chain of this device is as follows:
            # 1. BootROM (SoC)
            # 2. Preloader
            # 3. bl2_ext (LK)
            # 4. TEE
            # 5. GenieZone (GZ)
            # 6. lk or aee (LK)
            # 7. Linux kernel (boot)
            # 8. ...
            #
            # BootROM is the first stage and is not modifiable (it's masked ROM) and
            # it ALWAYS verifies and loads the Preloader against the fused root key. 
            # Then, under normal circumstances, the Preloader verifies and loads bl2_ext, 
            # which is the first partition of 'lk' to get verified and loaded. Then
            # bl2_ext takes control of the boot process and verifies and loads
            # the next partitions: TEE, GZ, LK, and so on.
            #
            # HOWEVER, this is not the case when seccfg is unlocked. When this
            # happens, the Preloader DOES NOT verify bl2_ext even though bl2_ext
            # itself still verifies the subsequent partitions. This means that one
            # can arbitrarily modify bl2_ext so it does not verify the next
            # partitions, which would lead to a full takeover of the secure boot chain.
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                # This is because every partition inside the LK image has its own function
                # that is called to verify the next partition. We take advantage of the fact
                # that the signature of the function is always the same, so we can apply the
                # patch to all of them at once.
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),

            # Since at this point we have full control over the boot chain, we can
            # easily patch the lk partition, which is the one that takes care of
            # setting up the boot state of the device, which is then used by Android
            # to determine whether the device is locked or unlocked.
            #
            # The goal here is to spoof the boot state to always be set to green and
            # thus trick TEE and Android into thinking that the device hasn't been
            # tampered with so we can pass STRONG, DEVICE and BASIC Play Store Integrity
            # checks.
            #
            # Most likely the first two patches are not needed, but it's better to be safe
            # than sorry.
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='a8 03 00 f0 00 21 01 b9 c0 03 5f d6',
                replacement='a8 03 00 f0 1f 21 01 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='24 74 01 94 20 01 00 36',
                replacement='24 74 01 94 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            
        },

        # This is the virtual address where 'lk' (not the image but the partition)
        # is loaded in memory. You can obtain this address by looking at the
        # 'expdb' partition of the device, which contains boot logs.
        base=0xFFFF000050F00000,
    ),
    Device(
        'Tetris',
        'CMF Phone 1',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='fd 7b c2 a8 c0 03 5f d6 a0 00 80 52 c0 03 5f d6 00 01 00 b4 fd 7b bf a9 fd 03 00 91 07 00 00 94 2f 00 00 94 00 00 00 12',
                replacement='fd 7b c2 a8 c0 03 5f d6 a0 00 80 52 c0 03 5f d6 00 00 80 52 c0 03 5f d6 fd 03 00 91 07 00 00 94 2f 00 00 94 00 00 00 12',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='68 04 00 f0 00 d9 04 b9 c0 03 5f d6',
                replacement='68 04 00 f0 1f d9 04 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_extra_check_1': PatchStage(
    'bypass_extra_check_1',
    pattern='f8 53 00 94 40 01 00 34',
    replacement='f8 53 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Skip extra Tetris verification check #1',
),

'bypass_extra_check_2': PatchStage(
    'bypass_extra_check_2',
    pattern='db 72 00 94 40 02 00 34',
    replacement='db 72 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Skip extra Tetris verification check #2',
),

'bypass_extra_check_3': PatchStage(
    'bypass_extra_check_3',
    pattern='e9 84 01 94 20 02 00 34',  # This covers the first bypass
    replacement='e9 84 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Skip extra Tetris verification check #3',
),

'bypass_extra_check_4': PatchStage(
    'bypass_extra_check_4',
    pattern='4d 84 01 94 20 01 00 34',
    replacement='4d 84 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Skip extra Tetris verification check #4',
),
'bypass_extra_check_5': PatchStage(
    'bypass_extra_check_5',
    pattern='48 84 01 94 60 01 00 34',
    replacement='48 84 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Skip extra Tetris verification check #5',
),
'bypass_extra_check_6': PatchStage(
            'bypass_extra_check_6',
            pattern='33 3f 00 94 a0 01 00 34',
            replacement='33 3f 00 94 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Skip verification check #6',
        ),
        'bypass_extra_check_7': PatchStage(
            'bypass_extra_check_7',
            pattern='2c 3f 00 94 c0 00 00 34',
            replacement='2c 3f 00 94 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Skip verification check #7',
        ),
        'bypass_extra_check_8': PatchStage(
            'bypass_extra_check_8',
            pattern='8a ce 01 94 a0 00 00 34',
            replacement='8a ce 01 94 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Skip verification check #8',
        ),
        'bypass_extra_check_9': PatchStage(
            'bypass_extra_check_9',
            pattern='2e 01 00 94 60 01 00 34',
            replacement='2e 01 00 94 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Skip verification check #9',
        ),
        'bypass_extra_check_10': PatchStage(
            'bypass_extra_check_10',
            pattern='e4 cd 01 94 a0 04 00 34',
            replacement='e4 cd 01 94 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Skip verification check #10',
        # Function-Cluster Bypasses for Tetris
        ),
'bypass_func_69714_1': PatchStage(
    'bypass_func_69714_1',
    pattern='96 6a 01 94 16 1d 00 35',
    replacement='96 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x69714 site 1'
),
'bypass_func_69714_2': PatchStage(
    'bypass_func_69714_2',
    pattern='7e 6a 01 94 d6 1a 00 35',
    replacement='7e 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x69714 site 2'
),
'bypass_func_69714_3': PatchStage(
    'bypass_func_69714_3',
    pattern='4d 6a 01 94 76 15 00 35',
    replacement='4d 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x69714 site 3'
),

'bypass_func_1f8bd4_1': PatchStage(
    'bypass_func_1f8bd4_1',
    pattern='4f 1c 01 94 39 01 00 34',
    replacement='4f 1c 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x1F8BD4 site 1'
),
'bypass_func_1f8bd4_2': PatchStage(
    'bypass_func_1f8bd4_2',
    pattern='60 f0 00 94 b3 00 00 34',
    replacement='60 f0 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x1F8BD4 site 2'
),
'bypass_func_1f8bd4_3': PatchStage(
    'bypass_func_1f8bd4_3',
    pattern='86 e6 00 94 b3 00 00 34',
    replacement='86 e6 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x1F8BD4 site 3'
),

'bypass_func_13b784_1': PatchStage(
    'bypass_func_13b784_1',
    pattern='1f f3 00 94 37 1f 00 35',
    replacement='1f f3 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x13B784 site 1'
),
'bypass_func_13b784_2': PatchStage(
    'bypass_func_13b784_2',
    pattern='80 f2 00 94 18 0c 00 35',
    replacement='80 f2 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x13B784 site 2'
),
'bypass_func_13b784_3': PatchStage(
    'bypass_func_13b784_3',
    pattern='74 f2 00 94 57 0b 00 35',
    replacement='74 f2 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x13B784 site 3'
),

'bypass_func_341a4_1': PatchStage(
    'bypass_func_341a4_1',
    pattern='e4 36 ff 97 01 08 00 34',
    replacement='e4 36 ff 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x341A4 site 1'
),
'bypass_func_341a4_2': PatchStage(
    'bypass_func_341a4_2',
    pattern='34 a5 fe 97 42 01 00 34',
    replacement='34 a5 fe 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x341A4 site 2'
),

'bypass_func_1cdb38_1': PatchStage(
    'bypass_func_1cdb38_1',
    pattern='f8 5f ff 97 01 08 00 34',
    replacement='f8 5f ff 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x1CDB38 site 1'
),
'bypass_func_1cdb38_2': PatchStage(
    'bypass_func_1cdb38_2',
    pattern='e4 d4 fe 97 42 01 00 34',
    replacement='e4 d4 fe 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass hub 0x1CDB38 site 2'
),
            
        },
        base=0xFFFF000050700000
    ),
    Device(
        'LG8n',
        'Tecno Pova 4 Pro',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='e8 02 00 b0 00 f1 0a b9 c0 03 5f d6',
                replacement='e8 02 00 b0 1f f1 0a b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security check - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
        },
        base=0xFFFF000050F00000
    ),
    Device(
        'LH7n',
        'Tecno Pova 5',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='a8 03 00 d0 00 29 0d b9 c0 03 5f d6',
                replacement='a8 03 00 d0 1f 29 0d b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
            # TARGET FUNCTION 1: 0x00069714 (1934 calls, 27 verification sites)
'bypass_func_69714_1': PatchStage(
    'bypass_func_69714_1',
    pattern='96 6a 01 94 16 1d 00 35',
    replacement='96 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x69714 call site 1',
),
'bypass_func_69714_2': PatchStage(
    'bypass_func_69714_2', 
    pattern='7e 6a 01 94 d6 1a 00 35',
    replacement='7e 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x69714 call site 2',
),
'bypass_func_69714_3': PatchStage(
    'bypass_func_69714_3',
    pattern='4d 6a 01 94 76 15 00 35', 
    replacement='4d 6a 01 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x69714 call site 3',
),

# TARGET FUNCTION 2: 0x001F8BD4 (1308 calls, 13 verification sites) 
'bypass_func_1f8bd4_1': PatchStage(
    'bypass_func_1f8bd4_1',
    pattern='4f 1c 01 94 39 01 00 34',
    replacement='4f 1c 01 94 1f 20 03 d5', 
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x1F8BD4 call site 1',
),
'bypass_func_1f8bd4_2': PatchStage(
    'bypass_func_1f8bd4_2',
    pattern='60 f0 00 94 b3 00 00 34',
    replacement='60 f0 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL, 
    description='Bypass verification function 0x1F8BD4 call site 2',
),
'bypass_func_1f8bd4_3': PatchStage(
    'bypass_func_1f8bd4_3',
    pattern='86 e6 00 94 b3 00 00 34',
    replacement='86 e6 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x1F8BD4 call site 3', 
),

# TARGET FUNCTION 3: 0x0013B784 (1232 calls, 21 verification sites)
'bypass_func_13b784_1': PatchStage(
    'bypass_func_13b784_1',
    pattern='1f f3 00 94 37 1f 00 35',
    replacement='1f f3 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x13B784 call site 1',
),
'bypass_func_13b784_2': PatchStage(
    'bypass_func_13b784_2',
    pattern='80 f2 00 94 18 0c 00 35', 
    replacement='80 f2 00 94 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x13B784 call site 2',
),
'bypass_func_13b784_3': PatchStage(
    'bypass_func_13b784_3',
    pattern='74 f2 00 94 57 0b 00 35',
    replacement='74 f2 00 94 1f 20 03 d5', 
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x13B784 call site 3',
),

# TARGET FUNCTIONS 4 & 5: Smaller but critical
'bypass_func_341a4_1': PatchStage(
    'bypass_func_341a4_1',
    pattern='e4 36 ff 97 01 08 00 34',
    replacement='e4 36 ff 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x341A4 call site 1',
),
'bypass_func_341a4_2': PatchStage(
    'bypass_func_341a4_2', 
    pattern='34 a5 fe 97 42 01 00 34',
    replacement='34 a5 fe 97 1f 20 03 d5',
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x341A4 call site 2',
),
'bypass_func_1cdb38_1': PatchStage(
    'bypass_func_1cdb38_1',
    pattern='f8 5f ff 97 01 08 00 34',
    replacement='f8 5f ff 97 1f 20 03 d5', 
    match_mode=MatchMode.ALL,
    description='Bypass verification function 0x1CDB38 call site 1',
),
'bypass_func_1cdb38_2': PatchStage(
    'bypass_func_1cdb38_2',
    pattern='e4 d4 fe 97 42 01 00 34',
    replacement='e4 d4 fe 97 1f 20 03 d5',
    match_mode=MatchMode.ALL, 
    description='Bypass verification function 0x1CDB38 call site 2',
),
        },
        base=0xFFFF000050F00000
    ),
    Device(
        'LG7n',
        'Tecno Pova 4',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='c8 02 00 f0 00 29 0a b9 c0 03 5f d6',
                replacement='c8 02 00 f0 1f 29 0a b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security check - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
        },
        base=0xFFFF000050F00000
    )
]
