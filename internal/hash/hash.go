package hash

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"git.mp.ls/mpls/shrike/internal/models"
)

// HashDomainSnapshot computes a SHA-256 hash of the normalized significant fields
// of a domain snapshot. Used for deduplication — only store when hash changes.
func HashDomainSnapshot(snap *models.DomainSnapshot) []byte {
	h := sha256.New()

	writeField(h, "registrar", ptrStr(snap.Registrar))
	writeField(h, "registrant_name", ptrStr(snap.RegistrantName))
	writeField(h, "registrant_org", ptrStr(snap.RegistrantOrg))
	writeField(h, "registrant_email", ptrStr(snap.RegistrantEmail))
	writeField(h, "registrant_country", ptrStr(snap.RegistrantCountry))

	ns := make([]string, len(snap.NameServers))
	copy(ns, snap.NameServers)
	sort.Strings(ns)
	writeField(h, "nameservers", strings.Join(ns, ","))

	sc := make([]string, len(snap.StatusCodes))
	copy(sc, snap.StatusCodes)
	sort.Strings(sc)
	writeField(h, "status", strings.Join(sc, ","))

	writeField(h, "created_date", ptrTimeStr(snap.CreatedDate))
	writeField(h, "updated_date", ptrTimeStr(snap.UpdatedDate))
	writeField(h, "expiry_date", ptrTimeStr(snap.ExpiryDate))
	writeField(h, "dnssec", ptrBoolStr(snap.DNSSEC))

	return h.Sum(nil)
}

func HashIPSnapshot(snap *models.IPSnapshot) []byte {
	h := sha256.New()
	writeField(h, "net_name", ptrStr(snap.NetName))
	writeField(h, "org_name", ptrStr(snap.OrgName))
	writeField(h, "description", ptrStr(snap.Description))
	writeField(h, "country", ptrStr(snap.Country))
	writeField(h, "abuse_contact", ptrStr(snap.AbuseContact))
	writeField(h, "status", ptrStr(snap.Status))
	writeField(h, "allocated_date", ptrTimeStr(snap.AllocatedDate))
	writeField(h, "updated_date", ptrTimeStr(snap.UpdatedDate))
	return h.Sum(nil)
}

func HashASNSnapshot(snap *models.ASNSnapshot) []byte {
	h := sha256.New()
	writeField(h, "name", ptrStr(snap.Name))
	writeField(h, "org_name", ptrStr(snap.OrgName))
	writeField(h, "description", ptrStr(snap.Description))
	writeField(h, "country", ptrStr(snap.Country))
	writeField(h, "allocated_date", ptrTimeStr(snap.AllocatedDate))
	return h.Sum(nil)
}

func HashDNSRecord(rec *models.DNSRecord) []byte {
	h := sha256.New()
	writeField(h, "type", rec.RecordType)
	writeField(h, "name", rec.Name)
	writeField(h, "value", rec.Value)
	writeField(h, "ttl", ptrIntStr(rec.TTL))
	writeField(h, "priority", ptrIntStr(rec.Priority))
	return h.Sum(nil)
}

func HashASNPrefix(prefix *models.ASNPrefix) []byte {
	h := sha256.New()
	writeField(h, "prefix", prefix.Prefix)
	pathStrs := make([]string, len(prefix.ASPath))
	for i, asn := range prefix.ASPath {
		pathStrs[i] = fmt.Sprintf("%d", asn)
	}
	writeField(h, "as_path", strings.Join(pathStrs, ","))
	return h.Sum(nil)
}

func writeField(h interface{ Write([]byte) (int, error) }, name, value string) {
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(value))
	h.Write([]byte{0})
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptrTimeStr(t interface{}) string {
	if t == nil {
		return ""
	}
	b, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(b)
}

func ptrBoolStr(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

func ptrIntStr(i *int) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%d", *i)
}
