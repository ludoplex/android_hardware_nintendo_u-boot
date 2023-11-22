# SPDX-License-Identifier:	GPL-2.0+
# Copyright (c) 2016, Google Inc.
#
# U-Boot Verified Boot Test

"""
This tests verified boot in the following ways:

For image verification:
- Create FIT (unsigned) with mkimage
- Check that verification shows that no keys are verified
- Sign image
- Check that verification shows that a key is now verified

For configuration verification:
- Corrupt signature and check for failure
- Create FIT (with unsigned configuration) with mkimage
- Check that image verification works
- Sign the FIT and mark the key as 'required' for verification
- Check that image verification works
- Corrupt the signature
- Check that image verification no-longer works

For pre-load header verification:
- Create FIT image with a pre-load header
- Check that signature verification succeeds
- Corrupt the FIT image
- Check that signature verification fails
- Launch an FIT image without a pre-load header
- Check that image verification fails

Tests run with both SHA1 and SHA256 hashing.
"""

import os
import shutil
import struct
import pytest
import u_boot_utils as util
import vboot_forge
import vboot_evil

# Only run the full suite on a few combinations, since it doesn't add any more
# test coverage.
TESTDATA = [
    ['sha1-basic', 'sha1', '', None, False, True, False, False],
    ['sha1-pad', 'sha1', '', '-E -p 0x10000', False, False, False, False],
    ['sha1-pss', 'sha1', '-pss', None, False, False, False, False],
    ['sha1-pss-pad', 'sha1', '-pss', '-E -p 0x10000', False, False, False, False],
    ['sha256-basic', 'sha256', '', None, False, False, False, False],
    ['sha256-pad', 'sha256', '', '-E -p 0x10000', False, False, False, False],
    ['sha256-pss', 'sha256', '-pss', None, False, False, False, False],
    ['sha256-pss-pad', 'sha256', '-pss', '-E -p 0x10000', False, False, False, False],
    ['sha256-pss-required', 'sha256', '-pss', None, True, False, False, False],
    ['sha256-pss-pad-required', 'sha256', '-pss', '-E -p 0x10000', True, True, False, False],
    ['sha384-basic', 'sha384', '', None, False, False, False, False],
    ['sha384-pad', 'sha384', '', '-E -p 0x10000', False, False, False, False],
    ['algo-arg', 'algo-arg', '', '-o sha256,rsa2048', False, False, True, False],
    ['sha256-global-sign', 'sha256', '', '', False, False, False, True],
    ['sha256-global-sign-pss', 'sha256', '-pss', '', False, False, False, True],
]

@pytest.mark.boardspec('sandbox')
@pytest.mark.buildconfigspec('fit_signature')
@pytest.mark.requiredtool('dtc')
@pytest.mark.requiredtool('fdtget')
@pytest.mark.requiredtool('fdtput')
@pytest.mark.requiredtool('openssl')
@pytest.mark.parametrize("name,sha_algo,padding,sign_options,required,full_test,algo_arg,global_sign",
                         TESTDATA)
def test_vboot(u_boot_console, name, sha_algo, padding, sign_options, required,
               full_test, algo_arg, global_sign):
    """Test verified boot signing with mkimage and verification with 'bootm'.

    This works using sandbox only as it needs to update the device tree used
    by U-Boot to hold public keys from the signing process.

    The SHA1 and SHA256 tests are combined into a single test since the
    key-generation process is quite slow and we want to avoid doing it twice.
    """
    def dtc(dts):
        """Run the device tree compiler to compile a .dts file

        The output file will be the same as the input file but with a .dtb
        extension.

        Args:
            dts: Device tree file to compile.
        """
        dtb = dts.replace('.dts', '.dtb')
        util.run_and_log(cons, 'dtc %s %s%s -O dtb '
                         '-o %s%s' % (dtc_args, datadir, dts, tmpdir, dtb))

    def dtc_options(dts, options):
        """Run the device tree compiler to compile a .dts file

        The output file will be the same as the input file but with a .dtb
        extension.

        Args:
            dts: Device tree file to compile.
            options: Options provided to the compiler.
        """
        dtb = dts.replace('.dts', '.dtb')
        util.run_and_log(cons, 'dtc %s %s%s -O dtb '
                         '-o %s%s %s' % (dtc_args, datadir, dts, tmpdir, dtb, options))

    def run_binman(dtb):
        """Run binman to build an image

        Args:
            dtb: Device tree file used as input file.
        """
        pythonpath = os.environ.get('PYTHONPATH', '')
        os.environ['PYTHONPATH'] = (
            f'{pythonpath}:' + f'{tmpdir}/../scripts/dtc/pylibfdt'
        )
        util.run_and_log(
            cons,
            [
                binman,
                'build',
                '-d',
                f"{tmpdir}/{dtb}",
                '-a',
                f"pre-load-key-path={tmpdir}",
                '-O',
                tmpdir,
                '-I',
                tmpdir,
            ],
        )
        os.environ['PYTHONPATH'] = pythonpath

    def run_bootm(sha_algo, test_type, expect_string, boots, fit=None):
        """Run a 'bootm' command U-Boot.

        This always starts a fresh U-Boot instance since the device tree may
        contain a new public key.

        Args:
            test_type: A string identifying the test type.
            expect_string: A string which is expected in the output.
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to
                    use.
            boots: A boolean that is True if Linux should boot and False if
                    we are expected to not boot
            fit: FIT filename to load and verify
        """
        if not fit:
            fit = f'{tmpdir}test.fit'
        cons.restart_uboot()
        with cons.log.section(f'Verified boot {sha_algo} {test_type}'):
            output = cons.run_command_list(
                [f'host load hostfs - 100 {fit}', 'fdt addr 100', 'bootm 100']
            )
        assert expect_string in ''.join(output)
        if boots:
            assert 'sandbox: continuing, as we cannot run' in ''.join(output)
        else:
            assert('sandbox: continuing, as we cannot run'
                   not in ''.join(output))

    def make_fit(its):
        """Make a new FIT from the .its source file.

        This runs 'mkimage -f' to create a new FIT.

        Args:
            its: Filename containing .its source.
        """
        util.run_and_log(cons, [mkimage, '-D', dtc_args, '-f', f'{datadir}{its}', fit])

    def sign_fit(sha_algo, options):
        """Sign the FIT

        Signs the FIT and writes the signature into it. It also writes the
        public key into the dtb.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to
                    use.
            options: Options to provide to mkimage.
        """
        args = [mkimage, '-F', '-k', tmpdir, '-K', dtb, '-r', fit]
        if options:
            args += options.split(' ')
        cons.log.action(f'{sha_algo}: Sign images')
        util.run_and_log(cons, args)

    def sign_fit_dtb(sha_algo, options, dtb):
        """Sign the FIT

        Signs the FIT and writes the signature into it. It also writes the
        public key into the dtb.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to
                    use.
            options: Options to provide to mkimage.
        """
        args = [mkimage, '-F', '-k', tmpdir, '-K', dtb, '-r', fit]
        if options:
            args += options.split(' ')
        cons.log.action(f'{sha_algo}: Sign images')
        util.run_and_log(cons, args)

    def sign_fit_norequire(sha_algo, options):
        """Sign the FIT

        Signs the FIT and writes the signature into it. It also writes the
        public key into the dtb. It does not mark key as 'required' in dtb.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to
                    use.
            options: Options to provide to mkimage.
        """
        args = [mkimage, '-F', '-k', tmpdir, '-K', dtb, fit]
        if options:
            args += options.split(' ')
        cons.log.action(f'{sha_algo}: Sign images')
        util.run_and_log(cons, args)

    def replace_fit_totalsize(size):
        """Replace FIT header's totalsize with something greater.

        The totalsize must be less than or equal to FIT_SIGNATURE_MAX_SIZE.
        If the size is greater, the signature verification should return false.

        Args:
            size: The new totalsize of the header

        Returns:
            prev_size: The previous totalsize read from the header
        """
        total_size = 0
        with open(fit, 'r+b') as handle:
            handle.seek(4)
            total_size = handle.read(4)
            handle.seek(4)
            handle.write(struct.pack(">I", size))
        return struct.unpack(">I", total_size)[0]

    def corrupt_file(fit, offset, value):
        """Corrupt a file

        To corrupt a file, a value is written at the specified offset

        Args:
            fit: The file to corrupt
            offset: Offset to write
            value: Value written
        """
        with open(fit, 'r+b') as handle:
            handle.seek(offset)
            handle.write(struct.pack(">I", value))

    def create_rsa_pair(name):
        """Generate a new RSA key paid and certificate

        Args:
            name: Name of of the key (e.g. 'dev')
        """
        public_exponent = 65537

        rsa_keygen_bits = 3072 if sha_algo == "sha384" else 2048
        util.run_and_log(cons, 'openssl genpkey -algorithm RSA -out %s%s.key '
                     '-pkeyopt rsa_keygen_bits:%d '
                     '-pkeyopt rsa_keygen_pubexp:%d' %
                     (tmpdir, name, rsa_keygen_bits, public_exponent))

        # Create a certificate containing the public key
        util.run_and_log(cons, 'openssl req -batch -new -x509 -key %s%s.key '
                         '-out %s%s.crt' % (tmpdir, name, tmpdir, name))

    def test_with_algo(sha_algo, padding, sign_options):
        """Test verified boot with the given hash algorithm.

        This is the main part of the test code. The same procedure is followed
        for both hashing algorithms.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to
                    use.
            padding: Either '' or '-pss', to select the padding to use for the
                    rsa signature algorithm.
            sign_options: Options to mkimage when signing a fit image.
        """
        # Compile our device tree files for kernel and U-Boot. These are
        # regenerated here since mkimage will modify them (by adding a
        # public key) below.
        dtc('sandbox-kernel.dts')
        dtc('sandbox-u-boot.dts')

        # Build the FIT, but don't sign anything yet
        cons.log.action(f'{sha_algo}: Test FIT with signed images')
        make_fit(f'sign-images-{sha_algo}{padding}.its')
        run_bootm(sha_algo, 'unsigned images', ' - OK' if algo_arg else 'dev-', True)

        # Sign images with our dev keys
        sign_fit(sha_algo, sign_options)
        run_bootm(sha_algo, 'signed images', 'dev+', True)

        # Create a fresh .dtb without the public keys
        dtc('sandbox-u-boot.dts')

        cons.log.action(f'{sha_algo}: Test FIT with signed configuration')
        make_fit(f'sign-configs-{sha_algo}{padding}.its')
        run_bootm(
            sha_algo,
            'unsigned config',
            f"{'sha256' if algo_arg else sha_algo}+ OK",
            True,
        )

        # Sign images with our dev keys
        sign_fit(sha_algo, sign_options)
        run_bootm(sha_algo, 'signed config', 'dev+', True)

        cons.log.action(f'{sha_algo}: Check signed config on the host')

        util.run_and_log(cons, [fit_check_sign, '-f', fit, '-k', dtb])

        if full_test:
            # Make sure that U-Boot checks that the config is in the list of
            # hashed nodes. If it isn't, a security bypass is possible.
            ffit = f'{tmpdir}test.forged.fit'
            shutil.copyfile(fit, ffit)
            with open(ffit, 'rb') as fd:
                root, strblock = vboot_forge.read_fdt(fd)
            root, strblock = vboot_forge.manipulate(root, strblock)
            with open(ffit, 'w+b') as fd:
                vboot_forge.write_fdt(root, strblock, fd)
            util.run_and_log_expect_exception(
                cons, [fit_check_sign, '-f', ffit, '-k', dtb],
                1, 'Failed to verify required signature')

            run_bootm(sha_algo, 'forged config', 'Bad Data Hash', False, ffit)

            # Try adding an evil root node. This should be detected.
            efit = f'{tmpdir}test.evilf.fit'
            shutil.copyfile(fit, efit)
            vboot_evil.add_evil_node(fit, efit, evil_kernel, 'fakeroot')

            util.run_and_log_expect_exception(
                cons, [fit_check_sign, '-f', efit, '-k', dtb],
                1, 'Failed to verify required signature')
            run_bootm(sha_algo, 'evil fakeroot', 'Bad FIT kernel image format',
                      False, efit)

            # Try adding an @ to the kernel node name. This should be detected.
            efit = f'{tmpdir}test.evilk.fit'
            shutil.copyfile(fit, efit)
            vboot_evil.add_evil_node(fit, efit, evil_kernel, 'kernel@')

            msg = 'Signature checking prevents use of unit addresses (@) in nodes'
            util.run_and_log_expect_exception(
                cons, [fit_check_sign, '-f', efit, '-k', dtb],
                1, msg)
            run_bootm(sha_algo, 'evil kernel@', msg, False, efit)

        # Create a new properly signed fit and replace header bytes
        make_fit(f'sign-configs-{sha_algo}{padding}.its')
        sign_fit(sha_algo, sign_options)
        bcfg = u_boot_console.config.buildconfig
        max_size = int(bcfg.get('config_fit_signature_max_size', 0x10000000), 0)
        existing_size = replace_fit_totalsize(max_size + 1)
        run_bootm(sha_algo, 'Signed config with bad hash', 'Bad Data Hash',
                  False)
        cons.log.action(f'{sha_algo}: Check overflowed FIT header totalsize')

        # Replace with existing header bytes
        replace_fit_totalsize(existing_size)
        run_bootm(sha_algo, 'signed config', 'dev+', True)
        cons.log.action(f'{sha_algo}: Check default FIT header totalsize')

        # Increment the first byte of the signature, which should cause failure
        sig = util.run_and_log(cons, f'fdtget -t bx {fit} {sig_node} value')
        byte_list = sig.split()
        byte = int(byte_list[0], 16)
        byte_list[0] = '%x' % (byte + 1)
        sig = ' '.join(byte_list)
        util.run_and_log(cons, f'fdtput -t bx {fit} {sig_node} value {sig}')

        run_bootm(sha_algo, 'Signed config with bad hash', 'Bad Data Hash',
                  False)

        cons.log.action(f'{sha_algo}: Check bad config on the host')
        util.run_and_log_expect_exception(
            cons, [fit_check_sign, '-f', fit, '-k', dtb],
            1, 'Failed to verify required signature')

    def test_required_key(sha_algo, padding, sign_options):
        """Test verified boot with the given hash algorithm.

        This function tests if U-Boot rejects an image when a required key isn't
        used to sign a FIT.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to use
            padding: Either '' or '-pss', to select the padding to use for the
                    rsa signature algorithm.
            sign_options: Options to mkimage when signing a fit image.
        """
        # Compile our device tree files for kernel and U-Boot. These are
        # regenerated here since mkimage will modify them (by adding a
        # public key) below.
        dtc('sandbox-kernel.dts')
        dtc('sandbox-u-boot.dts')

        cons.log.action(f'{sha_algo}: Test FIT with configs images')

        # Build the FIT with prod key (keys required) and sign it. This puts the
        # signature into sandbox-u-boot.dtb, marked 'required'
        make_fit(f'sign-configs-{sha_algo}{padding}-prod.its')
        sign_fit(sha_algo, sign_options)

        # Build the FIT with dev key (keys NOT required). This adds the
        # signature into sandbox-u-boot.dtb, NOT marked 'required'.
        make_fit(f'sign-configs-{sha_algo}{padding}.its')
        sign_fit_norequire(sha_algo, sign_options)

        # So now sandbox-u-boot.dtb two signatures, for the prod and dev keys.
        # Only the prod key is set as 'required'. But FIT we just built has
        # a dev signature only (sign_fit_norequire() overwrites the FIT).
        # Try to boot the FIT with dev key. This FIT should not be accepted by
        # U-Boot because the prod key is required.
        run_bootm(sha_algo, 'required key', '', False)

        # Build the FIT with dev key (keys required) and sign it. This puts the
        # signature into sandbox-u-boot.dtb, marked 'required'.
        make_fit(f'sign-configs-{sha_algo}{padding}.its')
        sign_fit(sha_algo, sign_options)

        # Set the required-mode policy to "any".
        # So now sandbox-u-boot.dtb two signatures, for the prod and dev keys.
        # Both the dev and prod key are set as 'required'. But FIT we just built has
        # a dev signature only (sign_fit() overwrites the FIT).
        # Try to boot the FIT with dev key. This FIT should be accepted by
        # U-Boot because the dev key is required and policy is "any" required key.
        util.run_and_log(cons, f'fdtput -t s {dtb} /signature required-mode any')
        run_bootm(sha_algo, 'multi required key', 'dev+', True)

        # Set the required-mode policy to "all".
        # So now sandbox-u-boot.dtb two signatures, for the prod and dev keys.
        # Both the dev and prod key are set as 'required'. But FIT we just built has
        # a dev signature only (sign_fit() overwrites the FIT).
        # Try to boot the FIT with dev key. This FIT should not be accepted by
        # U-Boot because the prod key is required and policy is "all" required key
        util.run_and_log(cons, f'fdtput -t s {dtb} /signature required-mode all')
        run_bootm(sha_algo, 'multi required key', '', False)

    def test_global_sign(sha_algo, padding, sign_options):
        """Test global image signature with the given hash algorithm and padding.

        Args:
            sha_algo: Either 'sha1' or 'sha256', to select the algorithm to use
            padding: Either '' or '-pss', to select the padding to use for the
                    rsa signature algorithm.
        """

        dtb = f'{tmpdir}sandbox-u-boot-global{padding}.dtb'
        cons.config.dtb = dtb

        # Compile our device tree files for kernel and U-Boot. These are
        # regenerated here since mkimage will modify them (by adding a
        # public key) below.
        dtc('sandbox-kernel.dts')
        dtc_options(f'sandbox-u-boot-global{padding}.dts', '-p 1024')

        # Build the FIT with dev key (keys NOT required). This adds the
        # signature into sandbox-u-boot.dtb, NOT marked 'required'.
        make_fit('simple-images.its')
        sign_fit_dtb(sha_algo, '', dtb)

        # Build the dtb for binman that define the pre-load header
        # with the global sigature.
        dtc(f'sandbox-binman{padding}.dts')

        # Run binman to create the final image with the not signed fit
        # and the pre-load header that contains the global signature.
        run_binman(f'sandbox-binman{padding}.dtb')

        # Check that the signature is correctly verified by u-boot
        run_bootm(
            sha_algo,
            'global image signature',
            'signature check has succeed',
            True,
            f"{tmpdir}sandbox.img",
        )

        # Corrupt the image (just one byte after the pre-load header)
        corrupt_file(f"{tmpdir}sandbox.img", 4096, 255);

        # Check that the signature verification fails
        run_bootm(
            sha_algo,
            'global image signature',
            'signature check has failed',
            False,
            f"{tmpdir}sandbox.img",
        )

        # Check that the boot fails if the global signature is not provided
        run_bootm(sha_algo, 'global image signature', 'signature is mandatory', False)

    cons = u_boot_console
    tmpdir = f'{os.path.join(cons.config.result_dir, name)}/'
    if not os.path.exists(tmpdir):
        os.mkdir(tmpdir)
    datadir = f'{cons.config.source_dir}/test/py/tests/vboot/'
    fit = f'{tmpdir}test.fit'
    mkimage = f'{cons.config.build_dir}/tools/mkimage'
    binman = f'{cons.config.source_dir}/tools/binman/binman'
    fit_check_sign = f'{cons.config.build_dir}/tools/fit_check_sign'
    dtc_args = f'-I dts -O dtb -i {tmpdir}'
    dtb = f'{tmpdir}sandbox-u-boot.dtb'
    sig_node = '/configurations/conf-1/signature'

    create_rsa_pair('dev')
    create_rsa_pair('prod')

    # Create a number kernel image with zeroes
    with open(f'{tmpdir}test-kernel.bin', 'wb') as fd:
        fd.write(500 * b'\0')

    # Create a second kernel image with ones
    evil_kernel = f'{tmpdir}test-kernel1.bin'
    with open(evil_kernel, 'wb') as fd:
        fd.write(500 * b'\x01')

    try:
        # We need to use our own device tree file. Remember to restore it
        # afterwards.
        old_dtb = cons.config.dtb
        cons.config.dtb = dtb
        if global_sign:
            test_global_sign(sha_algo, padding, sign_options)
        elif required:
            test_required_key(sha_algo, padding, sign_options)
        else:
            test_with_algo(sha_algo, padding, sign_options)
    finally:
        # Go back to the original U-Boot with the correct dtb.
        cons.config.dtb = old_dtb
        cons.restart_uboot()
