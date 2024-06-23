# QCA Linux kernel cryptography service

if (WITH_linux_PLUGIN STREQUAL "yes" OR LINUX)
    if(NOT LINUX)
        warning("Attempting to build Linux plugin for non-Linux target")
    endif()
    
    enable_plugin("linux")
    
    option(WITH_DRIVER_INTROSPECTION "Enable (or disable) Qt meta-property API for inspecting kernel crypto drivers." On)
    option(USING_AF_NETLINK "Enable (or disable) use of AF_NETLINK for kernel crypto driver discovery." On)
    option(USING_VM_SPLICE "Enable (or disable) use of ::vmsplice to avoid copying data between the kernelspace and userspace." On)
    
    configure_file(config-qca-linux.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-qca-linux.h)
    set (QCA_LINUX_SOURCES qca-linux.cpp)

    add_library(qca-linux ${PLUGIN_TYPE} ${QCA_LINUX_SOURCES})

    target_link_libraries(qca-linux Qt${QT_MAJOR_VERSION}::Core ${QCA_LIB_NAME})

    if(NOT DEVELOPER_MODE)
        install(TARGETS qca-linux
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")
    endif()

else ()
    disable_plugin("linux")
endif ()
