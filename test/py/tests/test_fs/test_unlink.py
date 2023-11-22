# SPDX-License-Identifier:      GPL-2.0+
# Copyright (c) 2018, Linaro Limited
# Author: Takahiro Akashi <takahiro.akashi@linaro.org>
#
# U-Boot File System:unlink Test

"""
This test verifies unlink operation (deleting a file or a directory)
on file system.
"""

import pytest
from fstest_helpers import assert_fs_integrity

@pytest.mark.boardspec('sandbox')
@pytest.mark.slow
class TestUnlink(object):
    def test_unlink1(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 1 - delete a file
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 1 - unlink (file)'):
            output = u_boot_console.run_command_list(
                [
                    f'host bind 0 {fs_img}',
                    f'{fs_type}rm host 0:0 dir1/file1',
                    f'{fs_type}ls host 0:0 dir1/file1',
                ]
            )
            assert('' == ''.join(output))

            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 dir1/')
            assert 'file1' not in output
            assert('file2' in output)
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink2(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 2 - delete many files
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 2 - unlink (many)'):
            output = u_boot_console.run_command(f'host bind 0 {fs_img}')

            for i in range(0, 20):
                output = u_boot_console.run_command_list([
                    '%srm host 0:0 dir2/0123456789abcdef%02x' % (fs_type, i),
                    '%sls host 0:0 dir2/0123456789abcdef%02x' % (fs_type, i)])
                assert('' == ''.join(output))

            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 dir2')
            assert('0 file(s), 2 dir(s)' in output)
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink3(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 3 - trying to delete a non-existing file should fail
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 3 - unlink (non-existing)'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}rm host 0:0 dir1/nofile']
            )
            assert('nofile: doesn\'t exist' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink4(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 4 - delete an empty directory
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 4 - unlink (directory)'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}rm host 0:0 dir4']
            )
            assert('' == ''.join(output))

            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 /')
            assert 'dir4' not in output
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink5(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 5 - trying to deleting a non-empty directory ".."
        should fail
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 5 - unlink ("non-empty directory")'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}rm host 0:0 dir5']
            )
            assert('directory is not empty' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink6(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 6 - trying to deleting a "." should fail
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 6 - unlink (".")'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}rm host 0:0 dir5/.']
            )
            assert('directory is not empty' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_unlink7(self, u_boot_console, fs_obj_unlink):
        """
        Test Case 7 - trying to deleting a ".." should fail
        """
        fs_type,fs_img = fs_obj_unlink
        with u_boot_console.log.section('Test Case 7 - unlink ("..")'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}rm host 0:0 dir5/..']
            )
            assert('directory is not empty' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)
