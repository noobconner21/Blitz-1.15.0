from fastapi import APIRouter
from . import hysteria
from . import warp
from . import telegram
from . import normalsub
from . import singbox
from . import ip
from . import misc
from . import extra_config

router = APIRouter()


router.include_router(hysteria.router, prefix='/hysteria')
router.include_router(warp.router, prefix='/warp')
router.include_router(telegram.router, prefix='/telegram')
router.include_router(normalsub.router, prefix='/normalsub')
router.include_router(singbox.router, prefix='/singbox')
router.include_router(ip.router, prefix='/ip')
router.include_router(extra_config.router, prefix='/extra-config', tags=['Config - Extra Config'])
router.include_router(misc.router)
