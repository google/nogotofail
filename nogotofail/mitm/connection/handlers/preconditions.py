r'''
Copyright 2015 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import os
from nogotofail.mitm.util import extras

def filter_preconditions(classes, logger=None):
    """Filter handlers whose preconditions are not met

    classes: list of nogotofail handler classes to filter
    logger: logging.Logger to optionally log the failure message of handlers whose preconditions are not met.
    Returns list of classes whose preconditions are met
    """
    filtered = []
    for cls in classes:
        status, message = cls.check_precondition()
        if status:
            filtered.append(cls)
        elif logger is not None:
            logger.warning("Disabling handler %s because preconditions not met: %s.", cls.name, message)
    return filtered

def _build_precondition_join_fn(cls, fn):
    """Build a check_precondition function that uses both the old precondition check as well as the new function fn

    cls: class whose check_precondition should be used as a base
    fn: check_precondition function to check
    Returns a function that can replace a handler check_precondition method
    """
    old_precondition = cls.check_precondition
    def check_precondition():
        result, message = fn()
        if not result:
            return result, message
        return old_precondition()
    return staticmethod(check_precondition)

def requires_files(files):
    """Decorator for creating a handler that requies files be present in the extras dir in order to run

    files: required files to be present for the handler to be available
    """
    def check_files_precondition():
        for file in files:
            if not os.path.exists(extras.get_extras_path(file)):
                return False, "required file %s not found" % (file)
        return True, ""
    def wrapper(cls):
        cls.check_precondition = _build_precondition_join_fn(cls, check_files_precondition)
        return cls
    return wrapper
