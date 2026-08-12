package policy

type Security struct {
	WorkloadIdentity bool `json:"workload_identity"`
	ManagedSecrets bool `json:"managed_secrets"`
	LeastPrivilegeIAM bool `json:"least_privilege_iam"`
	PublicDatabase bool `json:"public_database"`
	PublicAdminIngress bool `json:"public_admin_ingress"`
	PrivilegedContainer bool `json:"privileged_container"`
	ReadOnlyRootFS bool `json:"read_only_root_fs"`
	SAST bool `json:"sast"`
	SCA bool `json:"sca"`
	ContainerScan bool `json:"container_scan"`
	IaCScan bool `json:"iac_scan"`
	SecretScan bool `json:"secret_scan"`
	SignedArtifacts bool `json:"signed_artifacts"`
}

type Reliability struct {
	HealthChecks bool `json:"health_checks"`
	MinReplicas int `json:"min_replicas"`
	ZoneAware bool `json:"zone_aware"`
	RollbackAutomated bool `json:"rollback_automated"`
	SLODefined bool `json:"slo_defined"`
	IncidentOwner string `json:"incident_owner"`
	Runbook bool `json:"runbook"`
	BackupRestoreTest bool `json:"backup_restore_test"`
	QueueConcurrency int `json:"queue_concurrency"`
	QueueConcurrencyMax int `json:"queue_concurrency_max"`
}

type Velocity struct {
	BuildMinutes int `json:"build_minutes"`
	BuildBudgetMinutes int `json:"build_budget_minutes"`
	AutomatedDeployment bool `json:"automated_deployment"`
	ReusableServiceTemplate bool `json:"reusable_service_template"`
	PreviewEnvironments bool `json:"preview_environments"`
	SelfServiceObservability bool `json:"self_service_observability"`
}

type Cost struct {
	MonthlyBudgetUSD float64 `json:"monthly_budget_usd"`
	EstimatedMonthlyUSD float64 `json:"estimated_monthly_usd"`
	AutoscalingMax int `json:"autoscaling_max"`
	LogRetentionDays int `json:"log_retention_days"`
	IdleEnvironmentTTLHours int `json:"idle_environment_ttl_hours"`
	Owner string `json:"owner"`
}

type Contract struct {
	Service string `json:"service"`
	Environment string `json:"environment"`
	Cloud string `json:"cloud"`
	Security Security `json:"security"`
	Reliability Reliability `json:"reliability"`
	Velocity Velocity `json:"velocity"`
	Cost Cost `json:"cost"`
}

type Finding struct { Severity string `json:"severity"`; Code string `json:"code"`; Message string `json:"message"` }
type Result struct { Allowed bool `json:"allowed"`; Findings []Finding `json:"findings,omitempty"` }

func Evaluate(c Contract) Result {
	var f []Finding
	if c.Environment == "production" {
		s:=c.Security
		if !s.WorkloadIdentity { f=append(f,Finding{"critical","static_cloud_credentials","production workloads require workload identity"}) }
		if !s.ManagedSecrets { f=append(f,Finding{"critical","unmanaged_secrets","managed secret storage is required"}) }
		if !s.LeastPrivilegeIAM { f=append(f,Finding{"critical","iam_too_broad","production IAM must be least privilege"}) }
		if s.PublicDatabase { f=append(f,Finding{"critical","public_database","production database cannot be public"}) }
		if s.PublicAdminIngress { f=append(f,Finding{"critical","public_admin_ingress","administrative ingress cannot be public"}) }
		if s.PrivilegedContainer { f=append(f,Finding{"critical","privileged_container","privileged application containers are prohibited"}) }
		if !s.ReadOnlyRootFS { f=append(f,Finding{"high","writable_rootfs","read-only root filesystem is expected where practical"}) }
		if !(s.SAST && s.SCA && s.ContainerScan && s.IaCScan && s.SecretScan) { f=append(f,Finding{"high","security_scan_gap","SAST, SCA, container, IaC and secret scanning are required"}) }
		if !s.SignedArtifacts { f=append(f,Finding{"high","unsigned_artifact","production artifacts require provenance/signing"}) }

		r:=c.Reliability
		if !r.HealthChecks || r.MinReplicas<2 || !r.ZoneAware { f=append(f,Finding{"high","availability_baseline_missing","health checks, redundancy and zone awareness are required"}) }
		if !r.RollbackAutomated { f=append(f,Finding{"high","rollback_missing","automated rollback path is required"}) }
		if !r.SLODefined { f=append(f,Finding{"medium","slo_missing","service-level objective should be explicit"}) }
		if r.IncidentOwner=="" || !r.Runbook { f=append(f,Finding{"high","incident_readiness_missing","incident owner and runbook are required"}) }
		if !r.BackupRestoreTest { f=append(f,Finding{"high","recovery_untested","backup and restore must be tested"}) }
		if r.QueueConcurrencyMax>0 && r.QueueConcurrency>r.QueueConcurrencyMax { f=append(f,Finding{"high","queue_concurrency_unbounded","worker concurrency exceeds safety bound"}) }

		v:=c.Velocity
		if v.BuildBudgetMinutes>0 && v.BuildMinutes>v.BuildBudgetMinutes { f=append(f,Finding{"medium","build_budget_exceeded","CI duration exceeds developer-velocity budget"}) }
		if !v.AutomatedDeployment { f=append(f,Finding{"high","manual_deployment","production deployment should be automated"}) }
		if !v.ReusableServiceTemplate { f=append(f,Finding{"medium","golden_path_missing","service onboarding should use a reusable template"}) }

		k:=c.Cost
		if k.MonthlyBudgetUSD>0 && k.EstimatedMonthlyUSD>k.MonthlyBudgetUSD { f=append(f,Finding{"medium","cost_budget_exceeded","estimated workload cost exceeds monthly budget"}) }
		if k.AutoscalingMax<=0 { f=append(f,Finding{"high","autoscaling_unbounded","production autoscaling requires an upper bound"}) }
		if k.LogRetentionDays<=0 || k.LogRetentionDays>365 { f=append(f,Finding{"medium","log_retention_unbounded","log retention must be explicitly bounded"}) }
		if k.Owner=="" { f=append(f,Finding{"medium","cost_owner_missing","every production workload needs a cost owner"}) }
	}
	allowed:=true
	for _,x:=range f { if x.Severity=="critical" || x.Severity=="high" { allowed=false } }
	return Result{Allowed:allowed, Findings:f}
}
