use axplat::mem::{Aligned4K, pa, va};
use page_table_entry::{GenericPTE, MappingFlags, loongarch64::LA64PTE};
use crate::config::plat::{BOOT_STACK_SIZE, PHYS_VIRT_OFFSET};

// Virtualization manager initialization state
static mut VIRT_MGR_INIT: bool = false;
static mut NEXT_GID: u16 = 1; // GID 0 reserved for Host

// CSR address constants
const LOONGARCH_CSR_CPUCFG2: u64 = 0x702;   // CPU configuration register 2
const LOONGARCH_CSR_GTLBC: u64 = 0x15;      // Virtual machine TLB control register
const LOONGARCH_CSR_GSTAT: u64 = 0x50;      // Guest status register
const LOONGARCH_CSR_GCTL: u64 = 0x51;       // Guest control register
const LOONGARCH_CSR_GINTCTL: u64 = 0x52;    // Guest interrupt control register
const LOONGARCH_CSR_DMWIN0: u64 = 0x180;    // Direct mapping window 0
const LOONGARCH_CSR_DMWIN1: u64 = 0x181;    // Direct mapping window 1

#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L0: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L1: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

/// Initialize boot page table
unsafe fn init_boot_page_table() {
    unsafe {
        let l1_va = va!(&raw const BOOT_PT_L1 as usize);
        
        // L0 page table entry: Point to L1 page table
        BOOT_PT_L0[0] = LA64PTE::new_table(axplat::mem::virt_to_phys(l1_va));
        
        // Device memory mapping: 0-1GB (RW+device attributes)
        BOOT_PT_L1[0] = LA64PTE::new_page(
            pa!(0),
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::DEVICE,
            true,
        );
        
        // Kernel execution area: 2-3GB (RWX)
        BOOT_PT_L1[2] = LA64PTE::new_page(
            pa!(0x8000_0000),
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE,
            true,
        );
        
        // GPA->HPA mapping example: 1-2GB (RWX)
        // In actual virtual machines, should be dynamically allocated by VMM
        BOOT_PT_L1[1] = LA64PTE::new_page(
            pa!(0x4000_0000),
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE,
            true,
        );
    }
}

/// Enable floating-point and SIMD instruction support
fn enable_fp_simd() {
    #[cfg(feature = "fp-simd")]
    {
        axcpu::asm::enable_fp();
        axcpu::asm::enable_lsx();
    }
}

/// Allocate globally unique GID
unsafe fn allocate_gid() -> u16 {
    unsafe {
        let gid = NEXT_GID;
        NEXT_GID = NEXT_GID.wrapping_add(1);
        gid
    }
}

/// Enable Loongson Virtualization Extension (LVZ)
fn enable_virtualization() {
    unsafe {
        // 1. Check LVZ support
        let mut cpucfg2: u64;
        core::arch::asm!(
            "csrrd {}, {}", 
            out(reg) cpucfg2,
            const LOONGARCH_CSR_CPUCFG2,
            options(nomem, nostack),
        );

        // If LVZ is supported (bit 10)
        if (cpucfg2 & (1 << 10)) != 0 {
            // Mark virtualization as initialized
            VIRT_MGR_INIT = true;
            
            // 2. Configure GTLBC register
            // Get maximum MTLB entries (bits 0-5)
            let max_mtlb = (cpucfg2 & 0x3F) as u32;
            // Allocate 50% to Guest (reserve at least 8 entries for Host)
            let guest_mtlb = (max_mtlb / 2).max(8).min(max_mtlb - 8);
            
            // Configure GTLBC:
            // - GMTLBNum: Number of MTLB entries available to Guest
            // - useTGID=1: Use TGID field
            // - TGID=1: Default GID
            let gtlbc_config = (guest_mtlb << 0)  | // GMTLBNum
                               (1 << 12)          | // useTGID
                               (1 << 16);           // TGID=1
            
            core::arch::asm!(
                "csrwr {}, {}", 
                in(reg) gtlbc_config,
                const LOONGARCH_CSR_GTLBC,
                options(nomem, nostack),
            );

            // 3. Configure GSTAT register
            // Set default GID=1 (in Host mode)
            core::arch::asm!(
                "csrwr {}, {}", 
                in(reg) 1 << 16,
                const LOONGARCH_CSR_GSTAT,
                options(nomem, nostack),
            );
            
            // 4. Configure GCTL register (Guest control)
            // Default configuration: Trap all privileged instructions and exceptions
            let gctl_config = (1 << 7)  | // TOPI: Trap privileged instructions
                             (1 << 9)  | // TOTI: Trap timer instructions
                             (1 << 11) | // TOE: Trap exceptions
                             (1 << 13) | // TOP: Trap PLV modifications
                             (1 << 15);  // TOHU: Trap unimplemented CSR
            core::arch::asm!(
                "csrwr {}, {}", 
                in(reg) gctl_config,
                const LOONGARCH_CSR_GCTL,
                options(nomem, nostack),
            );
            
            // 5. Configure GINTCTL register (Guest interrupt control)
            // Default configuration: All interrupts managed by Host
            core::arch::asm!(
                "csrwr {}, {}", 
                in(reg) 0,
                const LOONGARCH_CSR_GINTCTL,
                options(nomem, nostack),
            );
        } else {
            // LVZ not supported, mark virtualization as disabled
            VIRT_MGR_INIT = false;
        }
    }
}

/// Initialize MMU
fn init_mmu() {
    axcpu::init::init_mmu(
        axplat::mem::virt_to_phys(va!(&raw const BOOT_PT_L0 as usize)),
        PHYS_VIRT_OFFSET,
    );
}

/// Create new virtual machine
pub unsafe fn create_vm() -> Option<u16> {
    unsafe {
        if !VIRT_MGR_INIT {
            return None;
        }
        
        // Allocate unique GID
        let gid = allocate_gid();
        
        // TODO: Create virtual machine data structure
        // - Allocate memory space
        // - Initialize guest CSR state
        // - Set up GPA->HPA mapping
        
        Some(gid)
    }
}

/// Start virtual machine
pub unsafe fn start_vm(gid: u16) {
    unsafe {
        if !VIRT_MGR_INIT {
            return;
        }
        
        // 1. Set current GID
        core::arch::asm!(
            "csrwr {}, {}", 
            in(reg) (gid as u64) << 16,
            const LOONGARCH_CSR_GSTAT,
            options(nomem, nostack),
        );
        
        // 2. Load virtual machine state
        // TODO: Load state from virtual machine data structure
        
        // 3. Switch to Guest mode
        core::arch::asm!(
            "ertn",
            options(nomem, nostack)
        );
    }
}

/// Primary CPU startup entry
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("
        // Configure direct mapping window
        ori         $t0, $zero, 0x1      # CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -2048      # UC, PLV0, 0x8000 xxxx xxxx xxxx
        csrwr       $t0, {}              # LOONGARCH_CSR_DMWIN0
        ori         $t0, $zero, 0x11     # CSR_DMW1_MAT | CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -1792      # CA, PLV0, 0x9000 xxxx xxxx xxxx
        csrwr       $t0, {}              # LOONGARCH_CSR_DMWIN1

        // Set up boot stack
        la.global   $sp, {boot_stack}
        li.d        $t0, {boot_stack_size}
        add.d       $sp, $sp, $t0

        // Initialize key components
        bl          {enable_fp_simd}     # Enable FP/SIMD
        bl          {enable_virtualization} # Enable virtualization
        bl          {init_boot_page_table} # Initialize page table
        bl          {init_mmu}           # Enable MMU

        // Jump to main function
        csrrd       $a0, 0x20            # cpuid
        li.d        $a1, 0               # DTB parameter placeholder
        la.global   $t0, {entry}
        jirl        $zero, $t0, 0",
        const LOONGARCH_CSR_DMWIN0,
        const LOONGARCH_CSR_DMWIN1,
        boot_stack_size = const BOOT_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        enable_fp_simd = sym enable_fp_simd,
        enable_virtualization = sym enable_virtualization,
        init_boot_page_table = sym init_boot_page_table,
        init_mmu = sym init_mmu,
        entry = sym axplat::call_main,
    )
}

/// Secondary CPU startup entry
#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn _start_secondary() -> ! {
    core::arch::naked_asm!("
        // Configure direct mapping window
        ori          $t0, $zero, 0x1     # CSR_DMW1_PLV0
        lu52i.d      $t0, $t0, -2048     # UC, PLV0, 0x8000 xxxx xxxx xxxx
        csrwr        $t0, {}             # LOONGARCH_CSR_DMWIN0
        ori          $t0, $zero, 0x11    # CSR_DMW1_MAT | CSR_DMW1_PLV0
        lu52i.d      $t0, $t0, -1792     # CA, PLV0, 0x9000 xxxx xxxx xxxx
        csrwr        $t0, {}             # LOONGARCH_CSR_DMWIN1
        
        // Set up SMP boot stack
        la.abs       $t0, {sm_boot_stack_top}
        ld.d         $sp, $t0,0

        // Initialize key components
        bl           {enable_fp_simd}    # Enable FP/SIMD
        bl           {enable_virtualization} # Enable virtualization
        bl           {init_mmu}          # Enable MMU

        // Jump to secondary core entry
        csrrd        $a0, 0x20           # cpuid
        la.global    $t0, {entry}
        jirl         $zero, $t0, 0",
        const LOONGARCH_CSR_DMWIN0,
        const LOONGARCH_CSR_DMWIN1,
        sm_boot_stack_top = sym super::mp::SMP_BOOT_STACK_TOP,
        enable_fp_simd = sym enable_fp_simd,
        enable_virtualization = sym enable_virtualization,
        init_mmu = sym init_mmu,
        entry = sym axplat::call_secondary_main,
    )
}