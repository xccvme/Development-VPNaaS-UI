package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"vpnaas/ui-goth/internal/auth"
	"vpnaas/ui-goth/internal/forms"
	"vpnaas/ui-goth/internal/model"
	"vpnaas/ui-goth/internal/views"
	"vpnaas/ui-goth/internal/winsetup"
)

func (s *Server) routesV2() {
	// Multi-Site S2S (/sites)
	s.mux.HandleFunc("GET /sites", s.authed(s.sitesPage))
	s.mux.HandleFunc("GET /sites/tabel", s.authed(s.sitesPage))
	s.mux.HandleFunc("GET /sites/baru", s.authed(s.siteForm))
	s.mux.HandleFunc("GET /sites/{id}/ubah", s.authed(s.siteForm))
	s.mux.HandleFunc("GET /sites/{id}/configure", s.authed(s.siteConfigure))
	s.mux.HandleFunc("GET /sites/{id}/disconnect", s.authed(s.confirmMultiSiteDisconnect))
	s.mux.HandleFunc("GET /sites/{id}/hapus", s.authed(s.confirm("sites")))
	s.mux.HandleFunc("POST /sites", s.mutating(s.saveMultiSite))
	s.mux.HandleFunc("PUT /sites/{id}", s.mutating(s.saveMultiSite))
	s.mux.HandleFunc("DELETE /sites/{id}", s.mutating(s.remove("sites")))
	s.mux.HandleFunc("POST /sites/{id}/connect", s.mutating(s.multiSiteAction("connect")))
	s.mux.HandleFunc("POST /sites/{id}/disconnect", s.mutating(s.multiSiteAction("disconnect")))
	s.mux.HandleFunc("GET /unduh/sites/{id}/{vendor}", s.authed(s.downloadMultiSiteConfig))

	// C2S explicit session disconnect
	s.mux.HandleFunc("POST /akun/{id}/disconnect", s.mutating(s.disconnectUserAll))
	s.mux.HandleFunc("POST /akun/{id}/sesi/{ike_id}/disconnect", s.mutating(s.disconnectUserOne))

	// Grup C2S (/grup)
	s.mux.HandleFunc("GET /grup", s.authed(s.groupsPage))
	s.mux.HandleFunc("GET /grup/tabel", s.authed(s.groupsPage))
	s.mux.HandleFunc("GET /grup/baru", s.authed(s.groupForm))
	s.mux.HandleFunc("GET /grup/{id}/ubah", s.authed(s.groupForm))
	s.mux.HandleFunc("GET /grup/{id}/hapus", s.authed(s.confirm("groups")))
	s.mux.HandleFunc("POST /grup", s.mutating(s.saveGroup))
	s.mux.HandleFunc("PUT /grup/{id}", s.mutating(s.saveGroup))
	s.mux.HandleFunc("DELETE /grup/{id}", s.mutating(s.remove("groups")))

	// Static Routing (/routing)
	s.mux.HandleFunc("GET /routing", s.authed(s.routesPage))
	s.mux.HandleFunc("GET /routing/tabel", s.authed(s.routesPage))
	s.mux.HandleFunc("GET /routing/baru", s.authed(s.routeForm))
	s.mux.HandleFunc("GET /routing/{id}/ubah", s.authed(s.routeForm))
	s.mux.HandleFunc("GET /routing/{id}/hapus", s.authed(s.confirm("routes")))
	s.mux.HandleFunc("POST /routing", s.mutating(s.saveRoute))
	s.mux.HandleFunc("PUT /routing/{id}", s.mutating(s.saveRoute))
	s.mux.HandleFunc("DELETE /routing/{id}", s.mutating(s.remove("routes")))

	// PKI & Certificates (/pki)
	s.mux.HandleFunc("GET /pki", s.authed(s.pkiPage))
	s.mux.HandleFunc("GET /pki/tabel", s.authed(s.pkiPage))
	s.mux.HandleFunc("GET /pki/baru", s.authed(s.certIssueForm))
	s.mux.HandleFunc("POST /pki/certs", s.mutating(s.issueCert))
	s.mux.HandleFunc("POST /pki/certs/{id}/revoke", s.mutating(s.revokeCert))
	s.mux.HandleFunc("POST /pki/server/rotate", s.mutating(s.rotateServerCert))
	s.mux.HandleFunc("GET /unduh/pki/ca.pem", s.authed(s.downloadPKIFile("pki/ca/cert", "vpnaas-ca.pem", "application/x-pem-file")))
	s.mux.HandleFunc("GET /unduh/pki/ca.crl", s.authed(s.downloadPKIFile("pki/crl", "vpnaas-ca.crl", "application/pkix-crl")))
	s.mux.HandleFunc("GET /unduh/pki/certs/{id}/bundle.json", s.authed(s.downloadCertBundle("pem", "application/json", "-bundle.json")))
	s.mux.HandleFunc("GET /unduh/pki/certs/{id}/bundle.p12", s.authed(s.downloadCertBundle("p12", "application/x-pkcs12", ".p12")))

	// Token API (/tokens)
	s.mux.HandleFunc("GET /tokens", s.authed(s.tokensPage))
	s.mux.HandleFunc("GET /tokens/tabel", s.authed(s.tokensPage))
	s.mux.HandleFunc("GET /tokens/baru", s.authed(s.tokenForm))
	s.mux.HandleFunc("POST /tokens", s.mutating(s.createAPIToken))
	s.mux.HandleFunc("DELETE /tokens/{id}", s.mutating(s.revokeAPIToken))

	// Diagnostics & Logs on /status
	s.mux.HandleFunc("POST /status/diagnostics", s.mutating(s.runDiagnostics))
	s.mux.HandleFunc("GET /status/logs", s.authed(s.loadLogs))
}

// ---------- helpers ----------

func (s *Server) lookupSiteGroupNames(r *http.Request) (map[int]string, map[int]string) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	siteNames, groupNames := map[int]string{}, map[int]string{}
	var sites []model.MultiSite
	var groups []model.Group
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "groups", nil, &groups) }()
	wg.Wait()
	for _, st := range sites {
		siteNames[st.ID] = st.Name
	}
	for _, g := range groups {
		groupNames[g.ID] = g.Name
	}
	return siteNames, groupNames
}

func (s *Server) lookupAllEntityNames(r *http.Request) (map[int]string, map[int]string, map[int]string) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	siteNames, userNames, groupNames := map[int]string{}, map[int]string{}, map[int]string{}
	var sites []model.MultiSite
	var users []model.User
	var groups []model.Group
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "users", nil, &users) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "groups", nil, &groups) }()
	wg.Wait()
	for _, st := range sites {
		siteNames[st.ID] = st.Name
	}
	for _, u := range users {
		userNames[u.ID] = u.Username
	}
	for _, g := range groups {
		groupNames[g.ID] = g.Name
	}
	return siteNames, userNames, groupNames
}

func extractIntSet(row map[string]any, key string) map[int]bool {
	set := map[int]bool{}
	if row == nil {
		return set
	}
	arr, _ := row[key].([]any)
	for _, item := range arr {
		if f, ok := item.(float64); ok {
			set[int(f)] = true
		}
	}
	return set
}

func formIntSet(vals []string) map[int]bool {
	set := map[int]bool{}
	for _, raw := range vals {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			set[n] = true
		}
	}
	return set
}

func (s *Server) populateUserFormChoices(r *http.Request, f *views.Form) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	var groups []model.Group
	var certs []model.CertRecord
	var gw map[string]any
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "groups", nil, &groups) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "pki/certs", nil, &certs) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "gateway", nil, &gw) }()
	wg.Wait()
	f.Sites = sites
	f.Groups = groups
	f.Certs = certs
	if lan, ok := gw["lan_cidr"].(string); ok && lan != "" && lan != "192.0.2.0/24" {
		f.VPCCIDR = lan
	}
}

func (s *Server) populateUserFormOptions(r *http.Request, f *views.Form) {
	s.populateUserFormChoices(r, f)
	if f.SelectedIDs == nil {
		f.SelectedIDs = map[string]map[int]bool{}
	}
	if f.ID > 0 {
		if row, err := s.findRecord(r, "users", f.ID); err == nil {
			f.SelectedIDs["allowed_sites"] = extractIntSet(row, "allowed_sites")
			f.SelectedIDs["groups"] = extractIntSet(row, "groups")
		}
	}
}

func (s *Server) populatePolicyFormOptions(r *http.Request, f *views.Form) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	var users []model.User
	var groups []model.Group
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "users", nil, &users) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "groups", nil, &groups) }()
	wg.Wait()
	f.Sites = sites
	f.Users = users
	f.Groups = groups
}

// ---------- Multi-Site S2S (/sites) ----------

func (s *Server) siteTable(r *http.Request, flash *views.Flash) views.SiteTable {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	_, err := s.up.JSON(ctx, "GET", "sites", nil, &sites)
	names := map[int]string{}
	for _, st := range sites {
		names[st.ID] = st.Name
	}
	q := r.URL.Query().Get("q")
	t := views.SiteTable{Total: len(sites), Query: q, Err: errText(err), Flash: flash, SiteNames: names}
	for _, st := range sites {
		if model.Matches(q, st.Name, st.Address, st.IKEID, string(st.Subnets), string(st.HubLocalTS), st.StatusLabel(), st.AuthLabel()) {
			t.Rows = append(t.Rows, st)
		}
	}
	return t
}

func (s *Server) sitesPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.siteTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.SitesTable(t))
		return
	}
	s.page(w, r, sess, "sites", "Multi-Site S2S", views.SitesPage(t))
}

func (s *Server) populateSiteFormOptions(r *http.Request, f *views.Form) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	var certs []model.CertRecord
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "pki/certs", nil, &certs) }()
	wg.Wait()
	f.Sites = sites
	f.Certs = certs
}

func (s *Server) siteForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	defaults := map[string]string{
		"allow_vpc": "on",
		"nat":       "on",
		"encap":     "on",
		"dpd_delay": "30",
	}
	f, ok := s.loadForm(w, r, "sites", []string{"name", "address", "ike_id", "auth_method", "cert_id", "subnets", "dpd_delay", "ike_proposals", "esp_proposals", "description"}, defaults)
	if !ok {
		return
	}
	if f.Values["address"] == forms.AnyAddress {
		f.Values["address"] = ""
	}
	f.Values["subnets"] = strings.Join(forms.SplitList(f.Values["subnets"]), "\n")
	f.SelectedIDs = map[string]map[int]bool{}
	if f.ID > 0 {
		if row, err := s.findRecord(r, "sites", f.ID); err == nil {
			f.SelectedIDs["peer_sites"] = extractIntSet(row, "peer_sites")
			for _, bk := range []string{"allow_vpc", "nat", "encap"} {
				if bv, ok := row[bk].(bool); ok && !bv {
					f.Values[bk] = ""
				} else {
					f.Values[bk] = "on"
				}
			}
		}
	}
	s.populateSiteFormOptions(r, &f)
	render(w, r, views.SiteForm(f))
}

func (s *Server) saveMultiSite(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id := 0
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			http.NotFound(w, r)
			return
		}
	}
	f := formFromRequest(r, id)
	for _, bk := range []string{"allow_vpc", "nat", "encap"} {
		f.Values[bk] = ternary(forms.Checkbox(r.PostForm, bk, true), "on", "")
	}
	f.SelectedIDs = map[string]map[int]bool{"peer_sites": formIntSet(r.PostForm["peer_sites"])}
	body, errs := forms.MultiSite(r.PostForm, id == 0)
	if len(errs) > 0 {
		f.Errs = errs
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.SiteForm(f))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	method, path := "POST", "sites"
	if id > 0 {
		method, path = "PUT", "sites/"+strconv.Itoa(id)
	}
	if _, err := s.up.JSON(ctx, method, path, body, nil); err != nil {
		f.Err = err.Error()
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.SiteForm(f))
		return
	}
	saved(w, "Site S2S berhasil disimpan")
}

func (s *Server) siteConfigure(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	_, err := s.up.JSON(ctx, "GET", "sites", nil, &sites)
	data := views.SiteConfigureData{Err: errText(err)}
	names := map[int]string{}
	for _, st := range sites {
		names[st.ID] = st.Name
	}
	for _, st := range sites {
		if st.ID == id {
			data.Site = st
			for _, pid := range st.PeerSites {
				if n, ok := names[pid]; ok {
					data.PeerNames = append(data.PeerNames, n)
				}
			}
			render(w, r, views.SiteConfigureModal(data))
			return
		}
	}
	if data.Err == "" {
		data.Err = "Site tidak ditemukan"
	}
	render(w, r, views.SiteConfigureModal(data))
}

func (s *Server) confirmMultiSiteDisconnect(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	row, err := s.findRecord(r, "sites", id)
	render(w, r, views.ConfirmModal(views.Confirm{
		Title: "Disconnect Site S2S", Message: "Putus tunnel site ini sekarang? Trafik ke/dari site akan berhenti sementara.",
		Name: strVal(row, "name"), URL: "/sites/" + strconv.Itoa(id) + "/disconnect",
		Button: "Disconnect", Target: "#sites-table", Method: "post", Err: errText(err),
	}))
}

func (s *Server) multiSiteAction(action string) handler {
	label := map[string]string{"connect": "Connect", "disconnect": "Disconnect"}[action]
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		id, ok := pathID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := s.ctx(r)
		defer cancel()
		var out map[string]any
		_, err := s.up.JSON(ctx, "POST", "sites/"+strconv.Itoa(id)+"/"+action, nil, &out)
		t := s.siteTable(r, nil)
		flash := &views.Flash{Message: label + " site #" + strconv.Itoa(id) + " berhasil"}
		if err != nil {
			flash = &views.Flash{Message: label + " gagal: " + err.Error(), Error: true}
		} else if o, ok := out["output"].(string); ok {
			flash.Output = o
		}
		t.Flash = flash
		w.Header().Set("HX-Trigger", `{"vpnaas:close":true}`)
		render(w, r, views.SitesTable(t))
	}
}

func (s *Server) downloadMultiSiteConfig(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	vendor := r.PathValue("vendor")
	valid := map[string]bool{"swanctl": true, "script": true, "mikrotik": true, "fortigate": true, "cisco": true}
	if !ok || !valid[vendor] {
		jsonError(w, http.StatusNotFound, "Vendor config tidak dikenal")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := s.up.Do(ctx, "GET", "sites/"+strconv.Itoa(id)+"/config", "vendor="+vendor, nil, "")
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !res.OK() {
		jsonError(w, res.Status, res.Detail())
		return
	}
	if cd := res.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(res.Body)
}

// ---------- C2S Multi-Platform Profiles & Session Disconnect ----------

func (s *Server) downloadUserFormat(format, ctype, prefix, ext string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		id, ok := pathID(r)
		if !ok {
			jsonError(w, http.StatusNotFound, "Akun tidak dikenal")
			return
		}
		ctx, cancel := s.ctx(r)
		defer cancel()
		res, err := s.up.Do(ctx, "GET", "users/"+strconv.Itoa(id)+"/profile", "format="+format, nil, "")
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !res.OK() {
			jsonError(w, res.Status, res.Detail())
			return
		}
		if cd := res.Header.Get("Content-Disposition"); cd != "" {
			w.Header().Set("Content-Disposition", cd)
		} else {
			w.Header().Set("Content-Disposition", `attachment; filename="`+prefix+strconv.Itoa(id)+ext+`"`)
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(res.Body)
	}
}

func (s *Server) disconnectUserAll(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	_, err := s.up.JSON(ctx, "POST", "users/"+strconv.Itoa(id)+"/disconnect", nil, nil)
	t := s.userTable(r, nil)
	if err != nil {
		t.Flash = &views.Flash{Message: "Gagal memutus sesi: " + err.Error(), Error: true}
	} else {
		t.Flash = &views.Flash{Message: "Sesi aktif akun #" + strconv.Itoa(id) + " diputus"}
	}
	render(w, r, views.UsersTable(t))
}

func (s *Server) disconnectUserOne(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id, ok := pathID(r)
	ikeID := r.PathValue("ike_id")
	ikeNum, ierr := strconv.Atoi(ikeID)
	if !ok || ierr != nil || ikeNum < 1 || strconv.Itoa(ikeNum) != ikeID {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	_, err := s.up.JSON(ctx, "POST", "users/"+strconv.Itoa(id)+"/sessions/"+ikeID+"/disconnect", nil, nil)
	if err != nil {
		render(w, r, views.UserSessions(model.User{}, "Gagal memutus sesi IKE #"+ikeID+": "+err.Error()))
		return
	}
	w.Header().Set("HX-Trigger", `{"vpnaas:changed":true}`)
	s.userSessions(w, r, sess)
}

// ---------- Grup C2S (/grup) ----------

func (s *Server) groupTable(r *http.Request, flash *views.Flash) views.GroupTable {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var groups []model.Group
	_, err := s.up.JSON(ctx, "GET", "groups", nil, &groups)
	siteNames, _ := s.lookupSiteGroupNames(r)
	q := r.URL.Query().Get("q")
	t := views.GroupTable{Total: len(groups), Query: q, Err: errText(err), Flash: flash, SiteNames: siteNames}
	for _, g := range groups {
		if model.Matches(q, g.Name, g.Description, model.Join(g.AllowedCIDRs), g.AdminLabel()) {
			t.Rows = append(t.Rows, g)
		}
	}
	return t
}

func (s *Server) groupsPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.groupTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.GroupsTable(t))
		return
	}
	s.page(w, r, sess, "grup", "Grup C2S", views.GroupsPage(t))
}

func (s *Server) groupForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	f, ok := s.loadForm(w, r, "groups", []string{"name", "description", "allowed_cidrs"}, nil)
	if !ok {
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	_, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites)
	f.Sites = sites
	f.SelectedIDs = map[string]map[int]bool{}
	if f.ID > 0 {
		if row, err := s.findRecord(r, "groups", f.ID); err == nil {
			f.SelectedIDs["allowed_sites"] = extractIntSet(row, "allowed_sites")
		}
	}
	render(w, r, views.GroupForm(f))
}

func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id := 0
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			http.NotFound(w, r)
			return
		}
	}
	f := formFromRequest(r, id)
	f.SelectedIDs = map[string]map[int]bool{"allowed_sites": formIntSet(r.PostForm["allowed_sites"])}
	body, errs := forms.Group(r.PostForm)
	if len(errs) > 0 {
		f.Errs = errs
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.GroupForm(f))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	method, path := "POST", "groups"
	if id > 0 {
		method, path = "PUT", "groups/"+strconv.Itoa(id)
	}
	if _, err := s.up.JSON(ctx, method, path, body, nil); err != nil {
		f.Err = err.Error()
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.GroupForm(f))
		return
	}
	saved(w, "Grup C2S berhasil disimpan")
}

// ---------- Static Routing (/routing) ----------

func (s *Server) routeTable(r *http.Request, flash *views.Flash) views.RouteTable {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var live struct {
		KernelAvailable bool                `json:"kernel_available"`
		StaticRoutes    []model.StaticRoute `json:"static_routes"`
		KernelRoutes    []map[string]any    `json:"kernel_routes"`
	}
	_, err := s.up.JSON(ctx, "GET", "routes/live", nil, &live)
	siteNames, _ := s.lookupSiteGroupNames(r)
	q := r.URL.Query().Get("q")
	t := views.RouteTable{
		Total:        len(live.StaticRoutes),
		KernelRoutes: live.KernelRoutes,
		KernelOK:     live.KernelAvailable,
		SiteNames:    siteNames,
		Query:        q,
		Err:          errText(err),
		Flash:        flash,
	}
	for _, rt := range live.StaticRoutes {
		if model.Matches(q, rt.Name, rt.DestinationCIDR, rt.Gateway, rt.Interface, rt.SyncStatus) {
			t.Rows = append(t.Rows, rt)
		}
	}
	return t
}

func (s *Server) routesPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.routeTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.RoutesTable(t))
		return
	}
	s.page(w, r, sess, "routing", "Static Routing", views.RoutesPage(t))
}

func (s *Server) routeForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	f, ok := s.loadForm(w, r, "routes", []string{"name", "destination_cidr", "gateway", "interface", "metric", "site_id", "description"}, map[string]string{"metric": "100"})
	if !ok {
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var sites []model.MultiSite
	_, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites)
	f.Sites = sites
	render(w, r, views.RouteForm(f))
}

func (s *Server) saveRoute(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id := 0
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			http.NotFound(w, r)
			return
		}
	}
	f := formFromRequest(r, id)
	body, errs := forms.Route(r.PostForm)
	if len(errs) > 0 {
		f.Errs = errs
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.RouteForm(f))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	method, path := "POST", "routes"
	if id > 0 {
		method, path = "PUT", "routes/"+strconv.Itoa(id)
	}
	if _, err := s.up.JSON(ctx, method, path, body, nil); err != nil {
		f.Err = err.Error()
		s.populateSiteFormOptions(r, &f)
		render(w, r, views.RouteForm(f))
		return
	}
	saved(w, "Static route berhasil disimpan")
}

// ---------- PKI & Certificates (/pki) ----------

func (s *Server) pkiData(r *http.Request, flash *views.Flash) views.PKIPageData {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var ca, srv map[string]any
	var certs []model.CertRecord
	var cerr error
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "pki/ca", nil, &ca) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "pki/server", nil, &srv) }()
	go func() { defer wg.Done(); _, cerr = s.up.JSON(ctx, "GET", "pki/certs", nil, &certs) }()
	wg.Wait()
	return views.PKIPageData{CA: ca, Server: srv, Certs: certs, Err: errText(cerr), Flash: flash}
}

func (s *Server) pkiPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d := s.pkiData(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.PKIContent(d))
		return
	}
	s.page(w, r, sess, "pki", "PKI & Sertifikat", views.PKIPage(d))
}

func (s *Server) certIssueForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	render(w, r, views.CertIssueForm(views.Form{Values: map[string]string{"target_type": "user", "validity_days": "365"}}))
}

func (s *Server) issueCert(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	f := formFromRequest(r, 0)
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		f.Errs = forms.Errors{"name": "Nama sertifikat wajib diisi"}
		render(w, r, views.CertIssueForm(f))
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("validity_days")))
	if err != nil || days < 1 || days > 1825 {
		f.Errs = forms.Errors{"validity_days": "Masa berlaku harus 1–1825 hari"}
		render(w, r, views.CertIssueForm(f))
		return
	}
	body := map[string]any{
		"name":          name,
		"target_type":   strings.TrimSpace(r.PostForm.Get("target_type")),
		"validity_days": days,
	}
	if san := strings.TrimSpace(r.PostForm.Get("san")); san != "" {
		body["san"] = san
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if _, err := s.up.JSON(ctx, "POST", "pki/certs", body, nil); err != nil {
		f.Err = err.Error()
		render(w, r, views.CertIssueForm(f))
		return
	}
	saved(w, "Sertifikat X.509 berhasil diterbitkan")
}

func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	_, err := s.up.JSON(ctx, "POST", "pki/certs/"+strconv.Itoa(id)+"/revoke", nil, nil)
	flash := &views.Flash{Message: "Sertifikat #" + strconv.Itoa(id) + " dicabut & CRL diperbarui"}
	if err != nil {
		flash = &views.Flash{Message: "Gagal mencabut sertifikat: " + err.Error(), Error: true}
	}
	render(w, r, views.PKIContent(s.pkiData(r, flash)))
}

func (s *Server) rotateServerCert(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	_, err := s.up.JSON(ctx, "POST", "pki/server/rotate", map[string]any{}, nil)
	flash := &views.Flash{Message: "Sertifikat server berhasil dirotasi & dimuat ulang"}
	if err != nil {
		flash = &views.Flash{Message: "Gagal rotasi sertifikat server: " + err.Error(), Error: true}
	}
	render(w, r, views.PKIContent(s.pkiData(r, flash)))
}

func (s *Server) downloadPKIFile(upstreamPath, fname, ctype string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		ctx, cancel := s.ctx(r)
		defer cancel()
		res, err := s.up.Do(ctx, "GET", upstreamPath, "", nil, "")
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !res.OK() {
			jsonError(w, res.Status, res.Detail())
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(res.Body)
	}
}

func (s *Server) downloadCertBundle(format, ctype, ext string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		id, ok := pathID(r)
		if !ok {
			jsonError(w, http.StatusNotFound, "Sertifikat tidak dikenal")
			return
		}
		ctx, cancel := s.ctx(r)
		defer cancel()
		res, err := s.up.Do(ctx, "GET", "pki/certs/"+strconv.Itoa(id)+"/bundle", "format="+format, nil, "")
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !res.OK() {
			jsonError(w, res.Status, res.Detail())
			return
		}
		if cd := res.Header.Get("Content-Disposition"); cd != "" {
			w.Header().Set("Content-Disposition", cd)
		} else {
			name, _ := winsetup.Filename("cert-" + strconv.Itoa(id))
			w.Header().Set("Content-Disposition", `attachment; filename="`+name+ext+`"`)
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(res.Body)
	}
}

// ---------- Token API (/tokens) ----------

func (s *Server) tokenTable(r *http.Request, flash *views.Flash) views.TokenTable {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var rows []model.APIToken
	_, err := s.up.JSON(ctx, "GET", "tokens", nil, &rows)
	return views.TokenTable{Rows: rows, Err: errText(err), Flash: flash}
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.tokenTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.TokensTable(t))
		return
	}
	s.page(w, r, sess, "tokens", "Token API", views.TokensPage(t))
}

func (s *Server) tokenForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	render(w, r, views.TokenForm(views.Form{Values: map[string]string{"role": "operator"}}))
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	f := formFromRequest(r, 0)
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		f.Errs = forms.Errors{"name": "Nama token wajib diisi"}
		render(w, r, views.TokenForm(f))
		return
	}
	body := map[string]any{
		"name": name,
		"role": strings.TrimSpace(r.PostForm.Get("role")),
	}
	if exp := strings.TrimSpace(r.PostForm.Get("expires_days")); exp != "" {
		d, err := strconv.Atoi(exp)
		if err != nil || d < 1 || d > 3650 {
			f.Errs = forms.Errors{"expires_days": "Masa berlaku harus 1–3650 hari"}
			render(w, r, views.TokenForm(f))
			return
		}
		body["expires_days"] = d
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var out struct {
		Name  string `json:"name"`
		Role  string `json:"role"`
		Token string `json:"token"`
	}
	if _, err := s.up.JSON(ctx, "POST", "tokens", body, &out); err != nil {
		f.Err = err.Error()
		render(w, r, views.TokenForm(f))
		return
	}
	w.Header().Set("HX-Trigger", `{"vpnaas:changed":true}`)
	render(w, r, views.TokenCreatedModal(out.Name, out.Role, out.Token))
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	_, err := s.up.JSON(ctx, "DELETE", "tokens/"+strconv.Itoa(id), nil, nil)
	flash := &views.Flash{Message: "Token #" + strconv.Itoa(id) + " berhasil dicabut"}
	if err != nil {
		flash = &views.Flash{Message: "Gagal mencabut token: " + err.Error(), Error: true}
	}
	render(w, r, views.TokensTable(s.tokenTable(r, flash)))
}

// ---------- Diagnostics & Logs (/status) ----------

func (s *Server) runDiagnostics(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	r.ParseForm()
	body := map[string]any{"target": strings.TrimSpace(r.PostForm.Get("target"))}
	if uid, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("source_user_id"))); err == nil && uid > 0 {
		body["source_user_id"] = uid
	}
	if sid, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("source_site_id"))); err == nil && sid > 0 {
		body["source_site_id"] = sid
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	var out map[string]any
	_, err := s.up.JSON(ctx, "POST", "diagnostics/check", body, &out)
	render(w, r, views.DiagResult(out, errText(err)))
}

func (s *Server) loadLogs(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	src := r.URL.Query().Get("source")
	if src == "" {
		src = "strongswan"
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := s.up.Do(ctx, "GET", "logs", "source="+url.QueryEscape(src)+"&lines=100", nil, "")
	if err != nil {
		render(w, r, views.LogsBox(src, nil, err.Error()))
		return
	}
	if !res.OK() {
		render(w, r, views.LogsBox(src, nil, res.Detail()))
		return
	}
	var out struct {
		Lines []string `json:"lines"`
	}
	_ = json.Unmarshal(res.Body, &out)
	render(w, r, views.LogsBox(src, out.Lines, ""))
}
