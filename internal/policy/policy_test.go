package policy
import "testing"

func safe() Contract {
	return Contract{
		Service:"scanner-worker",Environment:"production",Cloud:"aws",
		Security:Security{true,true,true,false,false,false,true,true,true,true,true,true,true},
		Reliability:Reliability{true,2,true,true,true,"platform-oncall",true,true,20,50},
		Velocity:Velocity{7,10,true,true,true,true},
		Cost:Cost{2500,1800,20,30,24,"platform"},
	}
}
func TestSafe(t *testing.T){ if !Evaluate(safe()).Allowed { t.Fatal("expected safe contract") } }
func TestPrivilegedContainerRejected(t *testing.T){ c:=safe(); c.Security.PrivilegedContainer=true; if Evaluate(c).Allowed { t.Fatal("expected reject") } }
func TestQueueConcurrencyRejected(t *testing.T){ c:=safe(); c.Reliability.QueueConcurrency=100; if Evaluate(c).Allowed { t.Fatal("expected reject") } }
func TestBuildBudgetWarns(t *testing.T){ c:=safe(); c.Velocity.BuildMinutes=14; if !Evaluate(c).Allowed { t.Fatal("warning should not block") } }
