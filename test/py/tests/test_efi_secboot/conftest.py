# SPDX-License-Identifier:      GPL-2.0+
# Copyright (c) 2019, Linaro Limited
# Author: AKASHI Takahiro <takahiro.akashi@linaro.org>

import os
import os.path
from subprocess import call, check_call, check_output, CalledProcessError
import pytest
from defs import *


#
# Fixture for UEFI secure boot test
#


@pytest.fixture(scope='session')
def efi_boot_env(request, u_boot_config):
    """Set up a file system to be used in UEFI secure boot test.

    Args:
        request: Pytest request object.
        u_boot_config: U-boot configuration.

    Return:
        A path to disk image to be used for testing
    """
    image_path = u_boot_config.persistent_data_dir
    image_path = f'{image_path}/test_efi_secboot.img'

    try:
        mnt_point = f'{u_boot_config.build_dir}/mnt_efisecure'
        check_call(f'rm -rf {mnt_point}', shell=True)
        check_call(f'mkdir -p {mnt_point}', shell=True)

        # suffix
        # *.key: RSA private key in PEM
        # *.crt: X509 certificate (self-signed) in PEM
        # *.esl: signature list
        # *.hash: message digest of image as signature list
        # *.auth: signed signature list in signature database format
        # *.efi: UEFI image
        # *.efi.signed: signed UEFI image

        # Create signature database
        # PK
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_PK/ -keyout PK.key -out PK.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} PK.crt PK.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-01" -c PK.crt -k PK.key PK PK.esl PK.auth',
            shell=True,
        )
        # PK_null for deletion
        check_call(
            f'cd {mnt_point}; touch PK_null.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-02" -c PK.crt -k PK.key PK PK_null.esl PK_null.auth',
            shell=True,
        )
        # KEK
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_KEK/ -keyout KEK.key -out KEK.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} KEK.crt KEK.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-03" -c PK.crt -k PK.key KEK KEK.esl KEK.auth',
            shell=True,
        )
        # db
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_db/ -keyout db.key -out db.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} db.crt db.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-04" -c KEK.crt -k KEK.key db db.esl db.auth',
            shell=True,
        )
        # db1
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_db1/ -keyout db1.key -out db1.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} db1.crt db1.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key db db1.esl db1.auth',
            shell=True,
        )
        # dbx (TEST_dbx certificate)
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_dbx/ -keyout dbx.key -out dbx.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} dbx.crt dbx.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key dbx dbx.esl dbx.auth',
            shell=True,
        )
        # dbx_hash (digest of TEST_db certificate)
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t 0 -s 256 db.crt dbx_hash.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key dbx dbx_hash.crl dbx_hash.auth',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t 0 -s 384 db.crt dbx_hash384.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key dbx dbx_hash384.crl dbx_hash384.auth',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t 0 -s 512 db.crt dbx_hash512.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key dbx dbx_hash512.crl dbx_hash512.auth',
            shell=True,
        )
        # dbx_hash1 (digest of TEST_db1 certificate)
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t 0 -s 256 db1.crt dbx_hash1.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-06" -c KEK.crt -k KEK.key dbx dbx_hash1.crl dbx_hash1.auth',
            shell=True,
        )
        # dbx_db (with TEST_db certificate)
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-05" -c KEK.crt -k KEK.key dbx db.esl dbx_db.auth',
            shell=True,
        )

        # Copy image
        check_call(
            f'cp {u_boot_config.build_dir}/lib/efi_loader/helloworld.efi {mnt_point}',
            shell=True,
        )

        # Sign image
        check_call(
            f'cd {mnt_point}; sbsign --key db.key --cert db.crt helloworld.efi',
            shell=True,
        )
        # Sign already-signed image with another key
        check_call(
            f'cd {mnt_point}; sbsign --key db1.key --cert db1.crt --output helloworld.efi.signed_2sigs helloworld.efi.signed',
            shell=True,
        )
        # Create a corrupted signed image
        check_call(
            f'cd {mnt_point}; sh {u_boot_config.source_dir}/test/py/tests/test_efi_secboot/forge_image.sh helloworld.efi.signed helloworld_forged.efi.signed',
            shell=True,
        )
        # Digest image
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}hash-to-efi-sig-list helloworld.efi db_hello.hash; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-07" -c KEK.crt -k KEK.key db db_hello.hash db_hello.auth',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}hash-to-efi-sig-list helloworld.efi.signed db_hello_signed.hash; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-03" -c KEK.crt -k KEK.key db db_hello_signed.hash db_hello_signed.auth',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-04-07" -c KEK.crt -k KEK.key dbx db_hello_signed.hash dbx_hello_signed.auth',
            shell=True,
        )

        check_call(
            f'virt-make-fs --partition=gpt --size=+1M --type=vfat {mnt_point} {image_path}',
            shell=True,
        )
        check_call(f'rm -rf {mnt_point}', shell=True)

    except CalledProcessError as exception:
        pytest.skip(f'Setup failed: {exception.cmd}')
        return
    else:
        yield image_path
    finally:
        call(f'rm -f {image_path}', shell=True)

#
# Fixture for UEFI secure boot test of intermediate certificates
#


@pytest.fixture(scope='session')
def efi_boot_env_intca(request, u_boot_config):
    """Set up a file system to be used in UEFI secure boot test
    of intermediate certificates.

    Args:
        request: Pytest request object.
        u_boot_config: U-boot configuration.

    Return:
        A path to disk image to be used for testing
    """
    image_path = u_boot_config.persistent_data_dir
    image_path = f'{image_path}/test_efi_secboot_intca.img'

    try:
        mnt_point = f'{u_boot_config.persistent_data_dir}/mnt_efi_secboot_intca'
        check_call(f'rm -rf {mnt_point}', shell=True)
        check_call(f'mkdir -p {mnt_point}', shell=True)

        # Create signature database
        # PK
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_PK/ -keyout PK.key -out PK.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} PK.crt PK.esl; {EFITOOLS_PATH}sign-efi-sig-list -c PK.crt -k PK.key PK PK.esl PK.auth',
            shell=True,
        )
        # KEK
        check_call(
            f'cd {mnt_point}; openssl req -x509 -sha256 -newkey rsa:2048 -subj /CN=TEST_KEK/ -keyout KEK.key -out KEK.crt -nodes -days 365',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} KEK.crt KEK.esl; {EFITOOLS_PATH}sign-efi-sig-list -c PK.crt -k PK.key KEK KEK.esl KEK.auth',
            shell=True,
        )

        # We will have three-tier hierarchy of certificates:
        #   TestRoot: Root CA (self-signed)
        #   TestSub: Intermediate CA (signed by Root CA)
        #   TestCert: User certificate (signed by Intermediate CA, and used
        #             for signing an image)
        #
        # NOTE:
        # I consulted the following EDK2 document for certificate options:
        #     BaseTools/Source/Python/Pkcs7Sign/Readme.md
        # Please not use them as they are in product system. They are
        # for test purpose only.

        # TestRoot
        check_call(
            f'cp {u_boot_config.source_dir}/test/py/tests/test_efi_secboot/openssl.cnf {mnt_point}',
            shell=True,
        )
        check_call(
            f'cd {mnt_point}; export OPENSSL_CONF=./openssl.cnf; openssl genrsa -out TestRoot.key 2048; openssl req -extensions v3_ca -new -x509 -days 365 -key TestRoot.key -out TestRoot.crt -subj "/CN=TEST_root/"; touch index.txt; touch index.txt.attr',
            shell=True,
        )
        # TestSub
        check_call(
            f'cd {mnt_point}; touch serial.new; export OPENSSL_CONF=./openssl.cnf; openssl genrsa -out TestSub.key 2048; openssl req -new -key TestSub.key -out TestSub.csr -subj "/CN=TEST_sub/"; openssl ca -in TestSub.csr -out TestSub.crt -extensions v3_int_ca -days 365 -batch -rand_serial -cert TestRoot.crt -keyfile TestRoot.key',
            shell=True,
        )
        # TestCert
        check_call(
            f'cd {mnt_point}; touch serial.new; export OPENSSL_CONF=./openssl.cnf; openssl genrsa -out TestCert.key 2048; openssl req -new -key TestCert.key -out TestCert.csr -subj "/CN=TEST_cert/"; openssl ca -in TestCert.csr -out TestCert.crt -extensions usr_cert -days 365 -batch -rand_serial -cert TestSub.crt -keyfile TestSub.key',
            shell=True,
        )
        # db
        #  for TestCert
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} TestCert.crt TestCert.esl; {EFITOOLS_PATH}sign-efi-sig-list -c KEK.crt -k KEK.key db TestCert.esl db_a.auth',
            shell=True,
        )
        #  for TestSub
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} TestSub.crt TestSub.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-07-16" -c KEK.crt -k KEK.key db TestSub.esl db_b.auth',
            shell=True,
        )
        #  for TestRoot
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-sig-list -g {GUID} TestRoot.crt TestRoot.esl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-07-17" -c KEK.crt -k KEK.key db TestRoot.esl db_c.auth',
            shell=True,
        )
        ## dbx (hash of certificate with revocation time)
        #  for TestCert
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t "2020-07-20" -s 256 TestCert.crt TestCert.crl; {EFITOOLS_PATH}sign-efi-sig-list -c KEK.crt -k KEK.key dbx TestCert.crl dbx_a.auth',
            shell=True,
        )
        #  for TestSub
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t "2020-07-21" -s 256 TestSub.crt TestSub.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-07-18" -c KEK.crt -k KEK.key dbx TestSub.crl dbx_b.auth',
            shell=True,
        )
        #  for TestRoot
        check_call(
            f'cd {mnt_point}; {EFITOOLS_PATH}cert-to-efi-hash-list -g {GUID} -t "2020-07-22" -s 256 TestRoot.crt TestRoot.crl; {EFITOOLS_PATH}sign-efi-sig-list -t "2020-07-19" -c KEK.crt -k KEK.key dbx TestRoot.crl dbx_c.auth',
            shell=True,
        )

        # Sign image
        # additional intermediate certificates may be included
        # in SignedData

        check_call(
            f'cp {u_boot_config.build_dir}/lib/efi_loader/helloworld.efi {mnt_point}',
            shell=True,
        )
        # signed by TestCert
        check_call(
            f'cd {mnt_point}; {SBSIGN_PATH}sbsign --key TestCert.key --cert TestCert.crt --out helloworld.efi.signed_a helloworld.efi',
            shell=True,
        )
        # signed by TestCert with TestSub in signature
        check_call(
            f'cd {mnt_point}; {SBSIGN_PATH}sbsign --key TestCert.key --cert TestCert.crt --addcert TestSub.crt --out helloworld.efi.signed_ab helloworld.efi',
            shell=True,
        )
        # signed by TestCert with TestSub and TestRoot in signature
        check_call(
            f'cd {mnt_point}; cat TestSub.crt TestRoot.crt > TestSubRoot.crt; {SBSIGN_PATH}sbsign --key TestCert.key --cert TestCert.crt --addcert TestSubRoot.crt --out helloworld.efi.signed_abc helloworld.efi',
            shell=True,
        )

        check_call(
            f'virt-make-fs --partition=gpt --size=+1M --type=vfat {mnt_point} {image_path}',
            shell=True,
        )
        check_call(f'rm -rf {mnt_point}', shell=True)

    except CalledProcessError as e:
        pytest.skip(f'Setup failed: {e.cmd}')
        return
    else:
        yield image_path
    finally:
        call(f'rm -f {image_path}', shell=True)
