include('userland.js');
include('lapse.js');
include('binloader.js');

// Check if userland run OK
if (typeof eboot_addr !== "undefined") {
    var ret = lapse();
    // Check if Lapse run OK
    if (ret) {
        // Spawn payload.bin
        binloader_init();
    }
    else {
        log("Something went wrong. Please reboot and try again.");
    }
}