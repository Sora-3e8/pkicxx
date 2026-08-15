cmake_minimum_required(VERSION 3.19)
project(aes VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

file(GLOB_RECURSE SRC_FILES *.cc *.cpp)

add_library(${PROJECT_NAME} STATIC ${SRC_FILES})

set_target_properties(${PROJECT_NAME}
  PROPERTIES
  CMAKE_CXX_STANDARD 11
  PREFIX ""
  CMAKE_CXX_STANDARD_REQUIRED ON
)

# Dependency lookup, replace PACKAGE_NAME by your package
find_package(OpenSSL 3.0 REQUIRED Crypto)

# Report missing dependencies to user
if(NOT OpenSSL_FOUND)
  message(FATAL_ERROR "Could not find OpenSSL required components: Crypto")
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC OpenSSL::Crypto )
target_link_libraries("${PROJECT_NAME}" PUBLIC hash )

target_include_directories(${PROJECT_NAME}
  PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../hash/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/tancrypt>"
)

install(TARGETS aes
  EXPORT tancryptTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/tancrypt
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/tancrypt
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tancrypt
)

file(GLOB_RECURSE PUBLIC_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)
install(FILES ${PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tancrypt/)
