variable "credentials_file" {
  description = "Path to the Google Cloud service account credentials JSON file"
  type        = string
}

variable "project" {
  description = "Google Cloud project name"
  type        = string
}

variable "network_name" {
  description = "Name of the VPC network"
  type        = string
}

variable "region" {
  description = "Region where resources will be created"
  type        = string
}

variable "weabpp_subnet" {
  description = "A webapp subnet to be created"
  type = object({
    subnet_name   = string
    ip_cidr_range = string
    subnet_region = string
  })
}
variable "db_subnet" {
  description = "A db subnet to be created"
  type = object({
    subnet_name   = string
    ip_cidr_range = string
    subnet_region = string
  })
}

variable "routing_mode_region" {
  description = "Region for routing mode"
  type        = string
}

variable "webapp_route" {
  description = "Webapp route configurations"
  type        = object({
    route_name= string
    route_dest_range= string
    route_gateway= string
    route_priority = number
    route_tags = list(string)

  })
}

variable "boot_disk" {
  type = object({
    initialize_params_image = string
    initialize_params_size  = string
    initialize_params_type  = string
  })
}

variable "machine_type" {
  type = string
}

variable "instance_name" {
  type = string
}

variable "network_interface_access_config" {
  type = string
}

variable "instance_service_account" {
  type = object({
    scopes = list(string)
  })
}

variable "shielded_instance_config" {
  type = object({
    enable_integrity_monitoring = bool
    enable_secure_boot          = bool
    enable_vtpm                 = bool
  })
}

variable "tag" {
  type = list(
    string
  )
}

variable "zones"{
  type = string
}

variable "firewall_rules" {
  type = object({
    name = string
    description = string
    target_tags = list(string)
    source = list(string)
  })
}

variable "firewall_rules_allow" {
  type = object({
    protocol = string
    ports = list(string)
  })
}

variable "firewall_rules_deny" {
  type = list(string)
}

variable "google_sql_username" {
  type = string
}

variable "google_password_rules" {
  type = object({
    length = number
    special = bool
  })
}

variable "networking_connection_private_vpc_service" {
  type = string
}

variable "peer_connector_block" {
  type = object({
    name = string
    address_type = string
    purpose = string
    prefix_length = number
  })
}

variable "database_instance_block" {
  type = object({
    name = string
    deletion_protection = bool
    database_version = string
  })
}

variable "settings_block" {
  type = object({
    availability_type = string
    disk_type         = string
    disk_size         = number
    tier              = string
    ip_configuration_ipv4_enabled = bool
    enabled = bool
    binary_log_enabled = bool
  })
}

variable "database_naming" {
  type = string
}

variable "script_file_path" {
  type = string
}

variable "rules_deny_name" {
  type = string
}

variable "record_details" {
  type = object({
    zone_name    = string
    dns_name     = string
    type         = string
  })
}

variable "admin_logging_binding" {
  type = object({
    admin_logging_role = string
    metric_writer_role = string
    topic_iam_role = string
    subscription_iam_role = string
    cloud_function_iam_role = string
  })
}

variable "service_account_details"{
  type = object({
    account_id   = string
    display_name = string
  })
}

variable "topic_name"{
  type = string
}

variable "mailgun_api_key"{
  type = string
}

variable "mailgun_domain"{
  type = string
}

variable "google_cloudfunctions_function_var"{
  type = object({
    name = string
    description = string
    runtime = string
    available_memory_mb = number
    event_trigger_event_type = string
    
  })
}

variable "google_vpc_access_connector_var"{
  type = object({
    name = string
    ip_cidr_range = string
  })
}

variable "google_pubsub_subscription_var"{
  type = object({
    name = string
    ack = number
  })
}

variable "google_storage_bucket_name"{
  type =  string
}

variable "google_storage_bucket_object"{
  type = string
}

variable "google_compute_health_check_variable"{
  type = object({
    name = string
    check_interval_sec = number
    timeout_sec = number
    healthy_threshold = number
    unhealthy_threshold = number
    http_health_check_port = number
    http_health_check_request_path = string
  })
}

variable "google_compute_region_autoscaler_variable"{
  type = object({
    name = string
    autoscaling_policy_max_replicas = number
    autoscaling_policy_min_replicas = number
    autoscaling_policy_cooldown_period = number
    autoscaling_policy_target = number
  })
}

variable "google_compute_region_instance_group_manager_variable" {
  type = object({
    name = string
    base_instance_name = string
    version_name = string
    named_port_name = string
    named_port_port = number
  })
}

variable "google_compute_managed_ssl_certificate_variable"{
  type = object({
    name = string
    managed_domains = string
  })
}

variable "google_compute_backend_service_variable" {
  type = object({
    name = string
    port_name = string
    protocol = string
    timeout_sec = number
  })
}

variable "google_compute_url_map_variable" {
  type = string
}

variable "google_compute_target_https_proxy_variable" {
  type = string
}

variable "google_compute_global_forwarding_rule_variable" {
  type = object({
    name = string
    port_range = string
  })
}

variable "google_kms_key_ring_name" {
  type = string
}

variable "google_kms_key_ring_iam_binding_variable" {
  type = object({
    name = string
    rotation_period = string
  })
}

variable "google_kms_crypto_key_variable" {
  type = object({
    name = string
    rotation_period = string
  })
}

variable "google_kms_crypto_key_iam_binding_variable" {
  type = object({
    role = string
  })
}

variable "google_kms_crypto_key_iam_binding_variable_bucket" {
  type = object({
    role = string
  })
}

variable "google_project_service_identity_service" {
  type = string
}
