# Run by CTest in place of a Python check when no Python 3 interpreter was found at configure
# time: exit 77, which the test's SKIP_RETURN_CODE reports as Skipped rather than passed.
message("no Python 3 interpreter: skipped")
cmake_language(EXIT 77)
