package main

# Roles are namespace-scoped resources. A Role without a namespace will be
# silently defaulted by the API server, which can result in permissions being
# granted in an unintended namespace. Require every Role to declare its
# namespace explicitly so intent is clear.
deny contains msg if {
  input.kind == "Role"
  not input.metadata.namespace
  msg := sprintf("Role %v must have a namespace set", [input.metadata.name])
}

# RoleBinding resources, similarly, should be namespace-scoped.
deny contains msg if {
  input.kind == "RoleBinding"
  not input.metadata.namespace
  msg := sprintf("RoleBinding %v must have a namespace set", [input.metadata.name])
}

# Validate that Deployments do not run as root
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"
}

# ClusterRole resources must not have a namespace applied. This is typically ignored, but good hygiene
# to omit to avoid confusion.
deny contains msg if {
  input.kind == "ClusterRole"
  input.metadata.namespace
  msg := sprintf("ClusterRole %v must not have a namespace set", [input.metadata.name])
}

# ClusterRoleBinding resources must not have a namespace applied. This is typically ignored, but good hygiene
# to omit to avoid confusion.
deny contains msg if {
  input.kind == "ClusterRoleBinding"
  input.metadata.namespace
  msg := sprintf("ClusterRoleBinding %v must not have a namespace set", [input.metadata.name])
}

# A ClusterRoleBinding must not be bound to a Role resource
deny contains msg if {
  input.kind == "ClusterRoleBinding"
  input.roleRef.kind == "Role"
  msg := sprintf("ClusterRoleBinding %v must reference a ClusterRole, not a Role", [input.metadata.name])
}

# A RoleBinding must not be bound to a ClusterRole resource
deny contains msg if {
  input.kind == "RoleBinding"
  input.roleRef.kind == "ClusterRole"
  msg := sprintf("RoleBinding %v must reference a Role, not a ClusterRole", [input.metadata.name])
}

deny contains msg if {
  input.kind in {"RoleBinding", "ClusterRoleBinding"}
  subject := input.subjects[_]
  subject.kind == "ServiceAccount"
  not subject.namespace
  msg := sprintf("%v %v has ServiceAccount subject %v without a namespace", [input.kind, input.metadata.name, subject.name])
}