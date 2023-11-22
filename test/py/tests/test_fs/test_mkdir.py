# SPDX-License-Identifier:      GPL-2.0+
# Copyright (c) 2018, Linaro Limited
# Author: Takahiro Akashi <takahiro.akashi@linaro.org>
#
# U-Boot File System:mkdir Test

"""
This test verifies mkdir operation on file system.
"""

import pytest
from fstest_helpers import assert_fs_integrity

@pytest.mark.boardspec('sandbox')
@pytest.mark.slow
class TestMkdir(object):
    def test_mkdir1(self, u_boot_console, fs_obj_mkdir):
        """
        Test Case 1 - create a directory under a root
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 1 - mkdir'):
            output = u_boot_console.run_command_list(
                [
                    f'host bind 0 {fs_img}',
                    f'{fs_type}mkdir host 0:0 dir1',
                    f'{fs_type}ls host 0:0 /',
                ]
            )
            assert('dir1/' in ''.join(output))

            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 dir1')
            assert('./'   in output)
            assert('../'  in output)
            assert_fs_integrity(fs_type, fs_img)


    def test_mkdir2(self, u_boot_console, fs_obj_mkdir):
        """
        Test Case 2 - create a directory under a sub-directory
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 2 - mkdir (sub-sub directory)'):
            output = u_boot_console.run_command_list(
                [
                    f'host bind 0 {fs_img}',
                    f'{fs_type}mkdir host 0:0 dir1/dir2',
                    f'{fs_type}ls host 0:0 dir1',
                ]
            )
            assert('dir2/' in ''.join(output))

            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 dir1/dir2')
            assert('./'   in output)
            assert('../'  in output)
            assert_fs_integrity(fs_type, fs_img)

    def test_mkdir3(self, u_boot_console, fs_obj_mkdir):
        """
        Test Case 3 - trying to create a directory with a non-existing
        path should fail
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 3 - mkdir (non-existing path)'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}mkdir host 0:0 none/dir3']
            )
            assert('Unable to create a directory' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_mkdir4(self, u_boot_console, fs_obj_mkdir):
        """
        Test Case 4 - trying to create "." should fail
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 4 - mkdir (".")'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}mkdir host 0:0 .']
            )
            assert('Unable to create a directory' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_mkdir5(self, u_boot_console, fs_obj_mkdir):
        """
        Test Case 5 - trying to create ".." should fail
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 5 - mkdir ("..")'):
            output = u_boot_console.run_command_list(
                [f'host bind 0 {fs_img}', f'{fs_type}mkdir host 0:0 ..']
            )
            assert('Unable to create a directory' in ''.join(output))
            assert_fs_integrity(fs_type, fs_img)

    def test_mkdir6(self, u_boot_console, fs_obj_mkdir):
        """
        'Test Case 6 - create as many directories as amount of directory
        entries goes beyond a cluster size)'
        """
        fs_type,fs_img = fs_obj_mkdir
        with u_boot_console.log.section('Test Case 6 - mkdir (create many)'):
            output = u_boot_console.run_command_list(
                [
                    f'host bind 0 {fs_img}',
                    f'{fs_type}mkdir host 0:0 dir6',
                    f'{fs_type}ls host 0:0 /',
                ]
            )
            assert('dir6/' in ''.join(output))

            for i in range(0, 20):
                output = u_boot_console.run_command(
                    '%smkdir host 0:0 dir6/0123456789abcdef%02x'
                    % (fs_type, i))
            output = u_boot_console.run_command(f'{fs_type}ls host 0:0 dir6')
            assert('0123456789abcdef00/'  in output)
            assert('0123456789abcdef13/'  in output)

            output = u_boot_console.run_command(
                f'{fs_type}ls host 0:0 dir6/0123456789abcdef13/.'
            )
            assert('./'   in output)
            assert('../'  in output)

            output = u_boot_console.run_command(
                f'{fs_type}ls host 0:0 dir6/0123456789abcdef13/..'
            )
            assert('0123456789abcdef00/'  in output)
            assert('0123456789abcdef13/'  in output)
            assert_fs_integrity(fs_type, fs_img)
