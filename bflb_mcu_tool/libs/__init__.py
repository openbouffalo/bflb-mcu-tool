# -*- coding:utf-8 -*-


import pylink
import telnetlib
import serial
import ecdsa

from . import bflb_version
from . import bflb_interface_jlink
from . import bflb_interface_uart
from . import bflb_interface_openocd
from . import bflb_ecdh
from . import bflb_eflash_loader
from . import bflb_efuse_boothd_create
from . import bflb_flash_select
from . import bflb_img_create
from . import bflb_img_loader
from . import bflb_pt_creater
from . import bflb_ro_params_device_tree
from . import bflb_ro_params_gen
from . import bflb_utils
from . import bflb_configobj
from . import bflb_fdt

try:
    import changeconf as cgc
    conf_sign = True
except ImportError:
    conf_sign = False
    
if conf_sign:
    from . import bl602
else:
    from . import bl60x
    from . import bl602
    from . import bl702
