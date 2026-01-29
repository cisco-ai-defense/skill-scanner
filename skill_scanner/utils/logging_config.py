# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Centralized logging configuration for Skill Scanner.

This module provides consistent logging setup across all components.
"""

import logging
import sys


def setup_logger(name: str, level: str | None = None, format_string: str | None = None) -> logging.Logger:
    """
    Set up a logger with consistent configuration.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string, uses default if None

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    skill_scanner_root = logging.getLogger("skill_scanner")
    if skill_scanner_root.level == logging.DEBUG and name.startswith("skill_scanner"):
        logger.setLevel(logging.DEBUG)
    elif level:
        logger.setLevel(getattr(logging, level.upper()))
    else:
        logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)

    default_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(format_string or default_format)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False

    return logger


def get_logger(name: str, level: str | None = None) -> logging.Logger:
    """
    Get a logger with standard configuration.

    Args:
        name: Logger name (typically __name__)
        level: Optional logging level override

    Returns:
        Configured logger instance
    """
    return setup_logger(name, level)


def set_verbose_logging(verbose: bool = False) -> None:
    """
    Enable or disable verbose logging for all skill_scanner loggers.

    Args:
        verbose: If True, set all existing skill_scanner loggers to DEBUG level
    """
    target_level = logging.DEBUG if verbose else logging.INFO

    root_logger = logging.getLogger("skill_scanner")
    root_logger.setLevel(target_level)

    for name in list(logging.Logger.manager.loggerDict.keys()):
        if name.startswith("skill_scanner"):
            logger = logging.getLogger(name)
            logger.setLevel(target_level)
            for handler in logger.handlers:
                handler.setLevel(target_level)
