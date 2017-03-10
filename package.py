import os
from subprocess import call

import shutil


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)

with open('requirements.txt') as f:
    lines = f.readlines()

shutil.rmtree('./dist', ignore_errors=True)
for req in lines:
    call(['pip2', 'install', req, '-t', './dist'])
copytree('./source', './dist')
shutil.make_archive('./curator-aws-es', 'zip', './dist')

