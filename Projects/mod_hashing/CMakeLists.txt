disable_rtti()

file(GLOB_RECURSE SOURCES *.cpp *.h)

if(MSVC)
	precompiled_header(pch)
endif()

new_library_shared(mod_hashing "${SOURCES}" "")

# Link with CryptoPP
target_link_libraries(mod_hashing cryptopp-static)

set_target_properties(mod_hashing PROPERTIES FOLDER modules)
