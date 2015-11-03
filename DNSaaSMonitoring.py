# Copyright 2014 Copyright (c) 2013-2015, OneSource, Portugal.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

__author__ = 'Claudio Marques / Bruno Sousa - OneSource'
__copyright__ = "Copyright (c) 2013-2015, Mobile Cloud Networking (MCN) project"
__credits__ = ["Claudio Marques - Bruno Sousa"]
__license__ = "Apache"
__version__ = "1.0"
__maintainer__ = "Claudio Marques - Bruno Sousa"
__email__ = "claudio@onesource.pt, bmsousa@onesource.pt"
__status__ = "Production"


import os
import subprocess



def process_exists(proc, name, id = 0):
    ps = subprocess.Popen("ps xa", shell = True, stdout = subprocess.PIPE)
    ps_pid = ps.pid
    output = ps.stdout.read()
    ps.stdout.close()
    ps.wait()

    for line in output.split("\n"):
        if line != "" and line != None:
            fields = line.split()
            pid = fields[0]
            pname = fields[4]

            if (id == 0):
                if (pname == proc):
                    if (pname == 'python'):
                        if (fields[5] == name):
                            return True
                        else:
                            return False
                    return True
            else:
                if (pid == proc):
                    return True
    return False


if process_exists('python', 'DNSaaS.py') == False:
    os.chdir('/DNSaaS/')
    os.system("python DNSaaS.py &")
else:
    print("running DNSaaS")

