provider "google" {
  credentials = file(var.credentials_file)
  project     = var.project
  region      = var.region
}
provider "google-beta" {
  credentials = file(var.credentials_file)
  project     = var.project
  region      = var.region
}
resource "google_compute_network" "my_vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  delete_default_routes_on_create = true
  routing_mode		  = var.routing_mode_region
}
resource "google_compute_subnetwork" "web_app_subnet" {
  name          = var.weabpp_subnet.subnet_name
  ip_cidr_range = var.weabpp_subnet.ip_cidr_range
  region        = var.weabpp_subnet.subnet_region
  network       = google_compute_network.my_vpc.id
  private_ip_google_access = true
}
resource "google_compute_subnetwork" "db_subnet" {
  name          = var.db_subnet.subnet_name
  ip_cidr_range = var.db_subnet.ip_cidr_range
  region        = var.db_subnet.subnet_region
  network       = google_compute_network.my_vpc.id
}
resource "google_compute_route" "web_app_route" {
  name            = var.webapp_route.route_name
  dest_range      = var.webapp_route.route_dest_range
  network         = google_compute_network.my_vpc.id
  next_hop_gateway = var.webapp_route.route_gateway
  priority        = var.webapp_route.route_priority
  tags            = var.webapp_route.route_tags
}
resource "google_compute_instance_template" "instance-4" {
  name         = var.instance_name
  machine_type = var.machine_type

  disk {
    source_image = var.boot_disk.initialize_params_image
    auto_delete  = true
    boot         = true
    disk_size_gb = var.boot_disk.initialize_params_size
    disk_type    = var.boot_disk.initialize_params_type
    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.my_instance_key.id
    }
  }

  network_interface {
    network    = google_compute_network.my_vpc.name
    subnetwork = google_compute_subnetwork.web_app_subnet.name

  }

  metadata = {
    db_host     = google_sql_database_instance.database_instance.ip_address[0].ip_address
    db_user     = google_sql_user.users.name
    db_password = random_password.password.result
  }
  metadata_startup_script = file(var.script_file_path)

  service_account {
    email  = google_service_account.service_account.email
    scopes = var.instance_service_account.scopes
  }

  shielded_instance_config {
    enable_integrity_monitoring = var.shielded_instance_config.enable_integrity_monitoring
    enable_secure_boot          = var.shielded_instance_config.enable_secure_boot
    enable_vtpm                 = var.shielded_instance_config.enable_vtpm
  }

  tags = var.tag
}
resource "google_compute_firewall" "rules" {
  project     = var.project
  name        = var.firewall_rules.name
  network     = google_compute_network.my_vpc.name
  description = var.firewall_rules.description

  allow {
    protocol  = var.firewall_rules_allow.protocol
    ports     = var.firewall_rules_allow.ports
  }
  target_tags = google_compute_instance_template.instance-4.tags
  source_ranges = [google_compute_global_forwarding_rule.https.ip_address, "35.191.0.0/16", "130.211.0.0/22"]
}

#resource "google_compute_firewall" "rules_deny" {
#  project     = var.project
#  name        = var.rules_deny_name
#  network     = google_compute_network.my_vpc.name
#  description = var.firewall_rules.description
#
#  deny {
#    protocol = var.firewall_rules_allow.protocol
#    ports    = var.firewall_rules_deny
#  }
#  target_tags = google_compute_instance.instance-4.tags
#  source_ranges = var.firewall_rules.source
#}

resource "google_compute_global_address" "peer_connector" {
  name         = var.peer_connector_block.name
  address_type = var.peer_connector_block.address_type
  purpose      = var.peer_connector_block.purpose
  network      = google_compute_network.my_vpc.id
  prefix_length = var.peer_connector_block.prefix_length
}
resource "google_service_networking_connection" "private_vpc_connection" {

  network                 = google_compute_network.my_vpc.id
  service                 = var.networking_connection_private_vpc_service
  reserved_peering_ranges = [google_compute_global_address.peer_connector.name]
}
resource "google_sql_database_instance" "database_instance" {
  name             = var.database_instance_block.name
  region           = var.region
  deletion_protection = var.database_instance_block.deletion_protection
  database_version = var.database_instance_block.database_version
  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    availability_type = var.settings_block.availability_type
    disk_type         = var.settings_block.disk_type
    disk_size         = var.settings_block.disk_size
    tier              = var.settings_block.tier
    ip_configuration {
      ipv4_enabled    = var.settings_block.ip_configuration_ipv4_enabled
      private_network = google_compute_network.my_vpc.self_link
    }
    backup_configuration {
      enabled = var.settings_block.enabled
      binary_log_enabled = var.settings_block.binary_log_enabled
    }
  }
}
resource "google_sql_database" "database" {
  name     = var.database_naming
  instance = google_sql_database_instance.database_instance.name
}
resource "google_sql_user" "users" {
  name     = var.google_sql_username
  password = random_password.password.result
  instance = google_sql_database_instance.database_instance.name
}
resource "random_password" "password" {
  length           = var.google_password_rules.length
  special          = var.google_password_rules.special
}
resource "google_service_account" "service_account"{
  account_id   = var.service_account_details.account_id
  display_name = var.service_account_details.display_name
}
resource "google_project_iam_binding" "admin-logging" {
  project = var.project
  role    = var.admin_logging_binding.admin_logging_role

  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}
resource "google_project_iam_binding" "metric-writer" {
  project = var.project
  role    = var.admin_logging_binding.metric_writer_role

  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}
resource "google_dns_record_set" "record" {
  managed_zone = var.record_details.zone_name
  name         = var.record_details.dns_name
  rrdatas      = [ google_compute_global_forwarding_rule.https.ip_address ]
  type         = var.record_details.type
}

resource "google_pubsub_topic" "topic" {
  name = var.topic_name
}

resource "google_pubsub_subscription" "subscription" {
  name  = var.google_pubsub_subscription_var.name
  topic = google_pubsub_topic.topic.name

  ack_deadline_seconds = var.google_pubsub_subscription_var.ack
}

resource "google_storage_bucket" "source_code_bucket" {
  name     = var.google_storage_bucket_name
  location = var.region
}

resource "google_storage_bucket_object" "source_code_object" {
  name   = var.google_storage_bucket_object
  bucket = google_storage_bucket.source_code_bucket.name
  source = "Archive.zip"
}

resource "google_cloudfunctions_function" "example_function" {
  name                  = var.google_cloudfunctions_function_var.name
  description           = var.google_cloudfunctions_function_var.description
  runtime               = var.google_cloudfunctions_function_var.runtime
  available_memory_mb   = var.google_cloudfunctions_function_var.available_memory_mb
  source_archive_bucket = google_storage_bucket.source_code_bucket.name
  source_archive_object = google_storage_bucket_object.source_code_object.name
  
  event_trigger {
    event_type = var.google_cloudfunctions_function_var.event_trigger_event_type
    resource   = google_pubsub_topic.topic.id
  }
  region = var.region
  service_account_email = google_service_account.service_account.email
  vpc_connector = google_vpc_access_connector.vpc_connector.id

  environment_variables = {
  DB_USER_DETAILS            = google_sql_user.users.name
  DB_PASSWORD_VALUE        = random_password.password.result
  DB_DATABASE_NAME            = google_sql_database.database.name
  DB_DATABASE_HOST            = google_sql_database_instance.database_instance.ip_address[0].ip_address
  MAILGUN_DOMAIN     = var.mailgun_domain
  MAILGUN_API_KEY    = var.mailgun_api_key
  DB_CONNECTION_NAME = google_sql_database_instance.database_instance.connection_name
  }
}

resource "google_project_iam_member" "cloud_function_iam" {
  project = var.project
  role    = var.admin_logging_binding.cloud_function_iam_role
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_pubsub_subscription_iam_binding" "subscription_iam" {
  subscription = google_pubsub_subscription.subscription.name
  role         = var.admin_logging_binding.subscription_iam_role

  members = [
    "serviceAccount:${google_service_account.service_account.email}",
  ]
}

resource "google_pubsub_topic_iam_binding" "topic_iam" {
  topic = google_pubsub_topic.topic.name
  role  = var.admin_logging_binding.topic_iam_role

  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

resource "google_vpc_access_connector" "vpc_connector" {
  name          = var.google_vpc_access_connector_var.name
  project       = var.project
  region        = var.region
  network       = google_compute_network.my_vpc.name
  ip_cidr_range = var.google_vpc_access_connector_var.ip_cidr_range
}

resource "google_compute_health_check" "default" {
  name               = var.google_compute_health_check_variable.name
  check_interval_sec = var.google_compute_health_check_variable.check_interval_sec
  timeout_sec        = var.google_compute_health_check_variable.timeout_sec
  healthy_threshold  = var.google_compute_health_check_variable.healthy_threshold
  unhealthy_threshold = var.google_compute_health_check_variable.healthy_threshold

  http_health_check {
    port = var.google_compute_health_check_variable.http_health_check_port
    request_path = var.google_compute_health_check_variable.http_health_check_request_path
  }
}

resource "google_compute_region_autoscaler" "default" {
  name   = var.google_compute_region_autoscaler_variable.name
  region = var.region
  target = google_compute_region_instance_group_manager.default.id

  depends_on = [
    google_compute_region_instance_group_manager.default
  ]

  autoscaling_policy {
    max_replicas    = var.google_compute_region_autoscaler_variable.autoscaling_policy_max_replicas
    min_replicas    = var.google_compute_region_autoscaler_variable.autoscaling_policy_min_replicas
    cooldown_period = var.google_compute_region_autoscaler_variable.autoscaling_policy_cooldown_period
    cpu_utilization {
      target = var.google_compute_region_autoscaler_variable.autoscaling_policy_target
    }
  }
}

resource "google_compute_region_instance_group_manager" "default" {
  name = var.google_compute_region_instance_group_manager_variable.name
  base_instance_name = var.google_compute_region_instance_group_manager_variable.base_instance_name
  region = var.region

  version {
    name              = var.google_compute_region_instance_group_manager_variable.version_name
    instance_template = google_compute_instance_template.instance-4.self_link
  }

  named_port {
    name = var.google_compute_region_instance_group_manager_variable.named_port_name
    port = var.google_compute_region_instance_group_manager_variable.named_port_port
  }
  auto_healing_policies {
    health_check      = google_compute_health_check.default.id
    initial_delay_sec = 30
  }
}


resource "google_compute_managed_ssl_certificate" "default" {
  name    = var.google_compute_managed_ssl_certificate_variable.name
  managed {
    domains = [var.google_compute_managed_ssl_certificate_variable.managed_domains]
  }
}

resource "google_compute_backend_service" "default" {
  name        = var.google_compute_backend_service_variable.name
  port_name   = var.google_compute_backend_service_variable.port_name
  protocol    = var.google_compute_backend_service_variable.protocol
  timeout_sec = var.google_compute_backend_service_variable.timeout_sec

  backend {
    group = google_compute_region_instance_group_manager.default.instance_group
  }

  health_checks = [google_compute_health_check.default.id]
}

resource "google_compute_url_map" "default" {
  name        = var.google_compute_url_map_variable
  default_service = google_compute_backend_service.default.id
}

resource "google_compute_target_https_proxy" "default" {
  name             = var.google_compute_target_https_proxy_variable
  url_map          = google_compute_url_map.default.id
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
}

resource "google_compute_global_forwarding_rule" "https" {
  name       = var.google_compute_global_forwarding_rule_variable.name
  target     = google_compute_target_https_proxy.default.id
  port_range = var.google_compute_global_forwarding_rule_variable.port_range
}

resource "google_kms_key_ring" "store-my-key" {
  location = var.region
  name     = var.google_kms_key_ring_name
}

data "google_storage_project_service_account" "my-account"{}

resource "google_kms_key_ring_iam_binding" "my-key-ring-binding" {
  key_ring_id = google_kms_key_ring.store-my-key.id
  members     = [
    "serviceAccount:${google_service_account.service_account.email}",
    "serviceAccount:${data.google_storage_project_service_account.my-account.email_address}",
    "serviceAccount:${google_project_service_identity.database.email}"
  ]
  role        = var.google_kms_crypto_key_iam_binding_variable_bucket.role
}

resource "google_kms_crypto_key" "my_instance_key"{
  name = "instance-key"
  key_ring = google_kms_key_ring.store-my-key.id
  rotation_period = var.google_kms_crypto_key_variable.rotation_period
}

resource "google_kms_crypto_key" "db_key"{
  name = "db-key"
  key_ring = google_kms_key_ring.store-my-key.id
  rotation_period = var.google_kms_crypto_key_variable.rotation_period
}

resource "google_kms_crypto_key" "bucket_key" {
  rotation_period = var.google_kms_crypto_key_variable.rotation_period
  name     = var.google_kms_crypto_key_variable.name
  key_ring = google_kms_key_ring.store-my-key.id
}

data "google_project" "my_project" {}

resource "google_kms_crypto_key_iam_binding" "instance_binding" {
  crypto_key_id = google_kms_crypto_key.my_instance_key.id
  role          = var.google_kms_crypto_key_iam_binding_variable.role
  members       = [
    "serviceAccount:service-${data.google_project.my_project.number}@compute-system.iam.gserviceaccount.com"
  ]
}

resource "google_kms_crypto_key_iam_binding" "db_binding" {
  crypto_key_id = google_kms_crypto_key.db_key.id
  members       = [
    "serviceAccount:${google_project_service_identity.database.email}"
  ]
  role          = var.google_kms_crypto_key_iam_binding_variable_bucket.role
}

resource "google_kms_crypto_key_iam_binding" "bucket_binding" {
  crypto_key_id = google_kms_crypto_key.bucket_key.id
  members       = [
    "serviceAccount:${data.google_storage_project_service_account.my-account.email_address}"
  ]
  role          = var.google_kms_crypto_key_iam_binding_variable_bucket.role
}

resource "google_project_service_identity" "database"{
  provider = google-beta
  project = var.project
  service = var.google_project_service_identity_service
}
