"""A-60: bootstrap стека защиты (CrowdSec + ClamAV + Wazuh) из приложения.

Публичный API модуля — `run_stack_bootstrap()` (пошаговое развёртывание
стека, идемпотентное) и `stack_status()` (честный статус Docker/контейнеров/
креденшелов без каких-либо изменений состояния). Реализация и её проектные
решения — `bootstrap.py`.
"""

from app.services.stack.bootstrap import run_stack_bootstrap, stack_status

__all__ = ["run_stack_bootstrap", "stack_status"]
