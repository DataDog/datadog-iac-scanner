variable "env" {
  type = string
}

resource "datadog_monitor" "m0" {
  count   = 5
  name    = "svc-0 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc0.errors{env:${var.env}}.as_count() > 100"
  message = "svc-0 is erroring in ${var.env}"
  tags    = ["service:svc-0", "env:${var.env}"]
}

resource "datadog_monitor" "m1" {
  count   = 5
  name    = "svc-1 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc1.errors{env:${var.env}}.as_count() > 100"
  message = "svc-1 is erroring in ${var.env}"
  tags    = ["service:svc-1", "env:${var.env}"]
}

resource "datadog_monitor" "m2" {
  count   = 5
  name    = "svc-2 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc2.errors{env:${var.env}}.as_count() > 100"
  message = "svc-2 is erroring in ${var.env}"
  tags    = ["service:svc-2", "env:${var.env}"]
}

resource "datadog_monitor" "m3" {
  count   = 5
  name    = "svc-3 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc3.errors{env:${var.env}}.as_count() > 100"
  message = "svc-3 is erroring in ${var.env}"
  tags    = ["service:svc-3", "env:${var.env}"]
}

resource "datadog_monitor" "m4" {
  count   = 5
  name    = "svc-4 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc4.errors{env:${var.env}}.as_count() > 100"
  message = "svc-4 is erroring in ${var.env}"
  tags    = ["service:svc-4", "env:${var.env}"]
}

resource "datadog_monitor" "m5" {
  count   = 5
  name    = "svc-5 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc5.errors{env:${var.env}}.as_count() > 100"
  message = "svc-5 is erroring in ${var.env}"
  tags    = ["service:svc-5", "env:${var.env}"]
}

resource "datadog_monitor" "m6" {
  count   = 5
  name    = "svc-6 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc6.errors{env:${var.env}}.as_count() > 100"
  message = "svc-6 is erroring in ${var.env}"
  tags    = ["service:svc-6", "env:${var.env}"]
}

resource "datadog_monitor" "m7" {
  count   = 5
  name    = "svc-7 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc7.errors{env:${var.env}}.as_count() > 100"
  message = "svc-7 is erroring in ${var.env}"
  tags    = ["service:svc-7", "env:${var.env}"]
}

resource "datadog_monitor" "m8" {
  count   = 5
  name    = "svc-8 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc8.errors{env:${var.env}}.as_count() > 100"
  message = "svc-8 is erroring in ${var.env}"
  tags    = ["service:svc-8", "env:${var.env}"]
}

resource "datadog_monitor" "m9" {
  count   = 5
  name    = "svc-9 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc9.errors{env:${var.env}}.as_count() > 100"
  message = "svc-9 is erroring in ${var.env}"
  tags    = ["service:svc-9", "env:${var.env}"]
}

resource "datadog_monitor" "m10" {
  count   = 5
  name    = "svc-10 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc10.errors{env:${var.env}}.as_count() > 100"
  message = "svc-10 is erroring in ${var.env}"
  tags    = ["service:svc-10", "env:${var.env}"]
}

resource "datadog_monitor" "m11" {
  count   = 5
  name    = "svc-11 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc11.errors{env:${var.env}}.as_count() > 100"
  message = "svc-11 is erroring in ${var.env}"
  tags    = ["service:svc-11", "env:${var.env}"]
}

resource "datadog_monitor" "m12" {
  count   = 5
  name    = "svc-12 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc12.errors{env:${var.env}}.as_count() > 100"
  message = "svc-12 is erroring in ${var.env}"
  tags    = ["service:svc-12", "env:${var.env}"]
}

resource "datadog_monitor" "m13" {
  count   = 5
  name    = "svc-13 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc13.errors{env:${var.env}}.as_count() > 100"
  message = "svc-13 is erroring in ${var.env}"
  tags    = ["service:svc-13", "env:${var.env}"]
}

resource "datadog_monitor" "m14" {
  count   = 5
  name    = "svc-14 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc14.errors{env:${var.env}}.as_count() > 100"
  message = "svc-14 is erroring in ${var.env}"
  tags    = ["service:svc-14", "env:${var.env}"]
}

resource "datadog_monitor" "m15" {
  count   = 5
  name    = "svc-15 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc15.errors{env:${var.env}}.as_count() > 100"
  message = "svc-15 is erroring in ${var.env}"
  tags    = ["service:svc-15", "env:${var.env}"]
}

resource "datadog_monitor" "m16" {
  count   = 5
  name    = "svc-16 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc16.errors{env:${var.env}}.as_count() > 100"
  message = "svc-16 is erroring in ${var.env}"
  tags    = ["service:svc-16", "env:${var.env}"]
}

resource "datadog_monitor" "m17" {
  count   = 5
  name    = "svc-17 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc17.errors{env:${var.env}}.as_count() > 100"
  message = "svc-17 is erroring in ${var.env}"
  tags    = ["service:svc-17", "env:${var.env}"]
}

resource "datadog_monitor" "m18" {
  count   = 5
  name    = "svc-18 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc18.errors{env:${var.env}}.as_count() > 100"
  message = "svc-18 is erroring in ${var.env}"
  tags    = ["service:svc-18", "env:${var.env}"]
}

resource "datadog_monitor" "m19" {
  count   = 5
  name    = "svc-19 error rate ${var.env}"
  type    = "metric alert"
  query   = "avg(last_5m):sum:svc19.errors{env:${var.env}}.as_count() > 100"
  message = "svc-19 is erroring in ${var.env}"
  tags    = ["service:svc-19", "env:${var.env}"]
}
