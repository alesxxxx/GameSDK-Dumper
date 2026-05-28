import re

with open('../kdmapper/kdmapper/include/intel_driver_resource.hpp', 'r') as f:
    content = f.read()

# Change namespace and guard
content = content.replace('intel_driver_resource', 'gsd_mapper_resource')
content = content.replace('#pragma once', '#pragma once\n// Auto-generated from Intel NAL driver binary. Not creative content.')

with open('src/resource.hpp', 'w') as f:
    f.write(content)

print('Generated src/resource.hpp')
