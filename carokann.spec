x64:
	
	load "bin/carokann.x64.o"
		make pic +gofirst

	# merge general services
    run "services.spec"

	# Generate a 128-bit XOR key for the payload
	generate $MASK 128

	# Encrypt and add payload to section 'payload'
    run "payload.spec"
		xor $MASK
		preplen
        link "payload"
		
#	load "shellcode.bin"
#		xor $MASK
#		preplen
#		link "payload"

	# Add XOR key to section 'mask'
	push $MASK
        preplen
        link "mask"

	export
