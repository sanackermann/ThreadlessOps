x64:

	load "bin/payload.x64.o"
		make pic +gofirst

	# merge general services
    run "services.spec"
    
	export
