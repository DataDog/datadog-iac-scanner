package generic.common

import rego.v1

# subject is a block; the engine locates the finding from _dd_id.
finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})

is_list(v) if is_array(v)
