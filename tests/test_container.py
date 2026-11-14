import pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class ContainerTest(unittest.TestCase):
 def test_compose_private_backend_and_persistence(self):
  text=(ROOT/'compose.yaml').read_text()
  self.assertIn('network_mode: host',text)
  self.assertIn('restart: always',text)
  self.assertIn('read_only: true',text)
  self.assertIn('ui-state:/var/lib/vpnaas-ui',text)
  self.assertFalse((ROOT/'install.sh').exists())
 def test_windows_opt_in_host_network_and_tunnel_defaults(self):
  text=(ROOT/'compose.windows.yaml').read_text()
  self.assertIn('network_mode: host',text)
  self.assertIn('127.0.0.1:18000',text)
  self.assertIn('127.0.0.1:8080',text)
  self.assertIn('./secrets/backend-api.key',text)
  self.assertIn('create_host_path: false',text)
  self.assertNotIn('      network: host',text)
  self.assertNotIn('ports:',text)
 def test_secret_files_excluded(self):
  for filename in ['.gitignore','.dockerignore']:
   text=(ROOT/filename).read_text()
   self.assertIn('*.key',text)
   self.assertIn('secrets/',text)
 def test_multistage_no_source_secrets(self):
  text=(ROOT/'Dockerfile').read_text()
  self.assertIn('golang:1.27.4',text)
  self.assertIn('CGO_ENABLED=0',text)
  self.assertIn('go test ./...',text)
  self.assertIn('COPY --from=build',text)
if __name__=='__main__':unittest.main()
