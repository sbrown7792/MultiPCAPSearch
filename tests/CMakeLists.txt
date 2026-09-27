find_package(Qt6 REQUIRED COMPONENTS Test)

qt_add_executable(tst_multipcapsearch
    tst_multipcapsearch.cpp
    testpcap.h
)
target_link_libraries(tst_multipcapsearch PRIVATE multipcapsearch_core Qt6::Test)

add_test(NAME tst_multipcapsearch COMMAND tst_multipcapsearch)
set_tests_properties(tst_multipcapsearch PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
