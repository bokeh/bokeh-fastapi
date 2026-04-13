TESTS_DIR='./bokeh/tests'
CONFTEST="${TESTS_DIR}/conftest.py"
BACKUP="${TESTS_DIR}/conftest.py.bak"

if [[ ! -f "${BACKUP}" ]]; then
  cp "${CONFTEST}" "${BACKUP}"
fi

cat "${BACKUP}" './conftest_patch.py' > "${CONFTEST}"
