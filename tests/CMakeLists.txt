find_package(Qt6 REQUIRED COMPONENTS Test)

qt_add_executable(tst_multipcapsearch
    tst_multipcapsearch.cpp
    testpcap.h
)
target_link_libraries(tst_multipcapsearch PRIVATE multipcapsearch_core Qt6::Test)

# Also write a plain-text report, which CI prints (Windows runners swallow the console output).
add_test(NAME tst_multipcapsearch
    COMMAND tst_multipcapsearch -o ${CMAKE_CURRENT_BINARY_DIR}/test-report.txt,txt -o -,txt)
set_tests_properties(tst_multipcapsearch PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
# Plain console program everywhere, so QtTest's output shows up in CI logs.
set_target_properties(tst_multipcapsearch PROPERTIES WIN32_EXECUTABLE FALSE MACOSX_BUNDLE FALSE)
