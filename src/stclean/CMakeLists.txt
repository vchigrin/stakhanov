add_executable(stclean
  main.cc
)


target_link_libraries(stclean
  base
  log4cplus
  redisclient
  stexecutorlib
)

target_include_directories(stclean PUBLIC
  ${CMAKE_CURRENT_BINARY_DIR}
  ${BOOST_INCLUDE}
  ${LOG4CPLUS_INCLUDE}
)

