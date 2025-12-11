### Integrations ###

resource "juju_integration" "jimm_openfga" {
  count      = var.openfga.offer_url != null || var.openfga.application_name != null ? 1 : 0
  model_uuid = var.model_uuid

  application {
    name     = juju_application.jimm.name
    endpoint = "openfga"
  }

  application {
    offer_url = var.openfga.offer_url != null ? var.openfga.offer_url : null
    name      = var.openfga.application_name != null ? var.openfga.application_name : null
  }
}

resource "juju_integration" "jimm_vault" {
  count      = var.vault.offer_url != null || var.vault.application_name != null ? 1 : 0
  model_uuid = var.model_uuid

  application {
    name     = juju_application.jimm.name
    endpoint = "vault"
  }

  application {
    offer_url = var.vault.offer_url != null ? var.vault.offer_url : null
    name      = var.vault.application_name != null ? var.vault.application_name : null
  }
}

resource "juju_integration" "jimm_postgresql" {
  count      = var.postgresql.offer_url != null || var.postgresql.application_name != null ? 1 : 0
  model_uuid = var.model_uuid

  application {
    name     = juju_application.jimm.name
    endpoint = "database"
  }

  application {
    offer_url = var.postgresql.offer_url != null ? var.postgresql.offer_url : null
    name      = var.postgresql.application_name != null ? var.postgresql.application_name : null
  }
}

resource "juju_integration" "jimm_oauth" {
  count      = var.oauth.offer_url != null || var.oauth.application_name != null ? 1 : 0
  model_uuid = var.model_uuid

  application {
    name = juju_application.jimm.name
  }

  application {
    offer_url = var.oauth.offer_url != null ? var.oauth.offer_url : null
    name      = var.oauth.application_name != null ? var.oauth.application_name : null
  }
}

resource "juju_integration" "jimm_ingress" {
  count      = var.ingress.offer_url != null || var.ingress.application_name != null ? 1 : 0
  model_uuid = var.model_uuid

  application {
    name     = juju_application.jimm.name
    endpoint = "ingress"
  }

  application {
    offer_url = var.ingress.offer_url != null ? var.ingress.offer_url : null
    name      = var.ingress.application_name != null ? var.ingress.application_name : null
  }
}

