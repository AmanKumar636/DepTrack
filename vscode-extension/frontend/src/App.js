import React, { useEffect, useState } from 'react';
import {
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Container,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  CssBaseline,
  Grid,
  Card,
  CardContent,
  CardHeader,
  CardActions,
  Button,
  Switch,
  Divider,
  useMediaQuery,
  Box,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Refresh as RefreshIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { SnackbarProvider, useSnackbar } from 'notistack';
import { Bar } from 'react-chartjs-2';
import logo from './assets/logo.png';
import background from './assets/background.jpg';

const drawerWidth = 240;
const getTheme = (darkMode) =>
  createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: darkMode ? '#90caf9' : '#1976d2' },
      secondary: { main: darkMode ? '#f48fb1' : '#dc004e' },
      background: { default: darkMode ? '#121212' : '#f4f6f8' },
    },
    typography: { fontFamily: 'Roboto, sans-serif' },
  });

function ScanNotifier({ scanResults }) {
  const { enqueueSnackbar } = useSnackbar();
  useEffect(() => {
    if (scanResults) {
      enqueueSnackbar(`Scan updated: ${scanResults.summary || 'New results available'}`, { variant: 'info' });
    }
  }, [scanResults, enqueueSnackbar]);
  return null;
}

function App() {
  const [scanResults, setScanResults] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const theme = getTheme(darkMode);
  const isSmallScreen = useMediaQuery('(max-width:600px)');

  useEffect(() => {
    function handleMessage(event) {
      const message = event.data;
      console.log("Webview received message:", message);
      if (message.command === 'snykScan') {
        console.log("Received Snyk scan data:", message.data);
        setScanResults(message.data);
      }
    }
    window.addEventListener('message', handleMessage);
    // Notify extension that App component has mounted
    window.parent.postMessage({ command: 'webviewMounted' }, '*');
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const severityCounts = { low: 0, medium: 0, high: 0 };
  if (scanResults && Array.isArray(scanResults.vulnerabilities)) {
    scanResults.vulnerabilities.forEach(vuln => {
      const sev = vuln.severity?.toLowerCase();
      if (severityCounts[sev] !== undefined) severityCounts[sev] += 1;
    });
  }
  const chartData = {
    labels: ["Low", "Medium", "High"],
    datasets: [{
      label: "Vulnerability Count",
      data: [severityCounts.low, severityCounts.medium, severityCounts.high],
      backgroundColor: ["#66bb6a", "#ffa726", "#ef5350"],
    }],
  };

  const drawer = (
    <div>
      <Toolbar sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <img src={logo} alt="DepTrack Logo" style={{ width: 50, marginRight: 8 }} />
        <Typography variant="h6" noWrap>DepTrack</Typography>
      </Toolbar>
      <List>
        <ListItem button key="Dashboard">
          <ListItemIcon><DashboardIcon /></ListItemIcon>
          <ListItemText primary="Dashboard" />
        </ListItem>
      </List>
    </div>
  );

  return (
    <ThemeProvider theme={theme}>
      <SnackbarProvider maxSnack={3}>
        <CssBaseline />
        <ScanNotifier scanResults={scanResults} />
        <div style={{ display: 'flex' }}>
          <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1, backgroundImage: `url(${background})`, backgroundSize: 'cover' }}>
            <Toolbar>
              <IconButton color="inherit" edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ mr: 2, display: { sm: 'none' } }}>
                <MenuIcon />
              </IconButton>
              <Typography variant="h6" noWrap sx={{ flexGrow: 1 }}>
                DepTrack Dashboard
              </Typography>
              <Switch
                checked={darkMode}
                onChange={() => setDarkMode(!darkMode)}
                color="default"
                inputProps={{ 'aria-label': 'toggle dark mode' }}
              />
              <Button variant="contained" startIcon={<RefreshIcon />} onClick={() => window.location.reload()} sx={{ ml: 2 }}>
                Refresh
              </Button>
              <Button variant="outlined" startIcon={<BugReportIcon />} onClick={() => console.log("Debug scan results:", scanResults)} sx={{ ml: 1 }}>
                Debug
              </Button>
            </Toolbar>
          </AppBar>

          <Drawer
            variant="permanent"
            sx={{
              width: drawerWidth,
              flexShrink: 0,
              [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' },
              display: { xs: 'none', sm: 'block' },
            }}
            open
          >
            {drawer}
          </Drawer>

          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(!mobileOpen)}
            ModalProps={{ keepMounted: true }}
            sx={{
              display: { xs: 'block', sm: 'none' },
              [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' },
            }}
          >
            {drawer}
          </Drawer>

          <main style={{ flexGrow: 1, padding: theme.spacing(3), marginTop: 64, background: theme.palette.background.default }}>
            <Container maxWidth="lg">
              <Grid container spacing={4}>
                <Grid item xs={12}>
                  <Card elevation={6} sx={{ background: 'linear-gradient(135deg, #2196f3 0%, #21cbf3 100%)', color: 'white' }}>
                    <CardHeader title="Scan Overview" />
                    <CardContent>
                      <Typography variant="h5">
                        {scanResults ? scanResults.summary || "Scan completed" : "Loading scan results..."}
                      </Typography>
                      {scanResults && scanResults.timestamp && (
                        <Typography variant="caption" display="block">
                          Last updated: {new Date(scanResults.timestamp).toLocaleString()}
                        </Typography>
                      )}
                    </CardContent>
                    <CardActions>
                      <Button variant="contained" startIcon={<RefreshIcon />} onClick={() => window.location.reload()}>
                        Refresh
                      </Button>
                    </CardActions>
                  </Card>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Card elevation={6}>
                    <CardHeader title="Vulnerability Severity" />
                    <CardContent>
                      <Bar data={chartData} />
                    </CardContent>
                  </Card>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Card elevation={6}>
                    <CardHeader title="Vulnerability Details" />
                    <CardContent>
                      {scanResults && scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 ? (
                        scanResults.vulnerabilities.map(vuln => (
                          <Box key={vuln.id || vuln.packageName} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {vuln.packageName} ({vuln.severity})
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {vuln.recommendation || "No recommendation provided"}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No vulnerabilities to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Card elevation={6}>
                    <CardHeader title="Outdated Dependencies" />
                    <CardContent>
                      {scanResults && scanResults.outdated && scanResults.outdated.length > 0 ? (
                        scanResults.outdated.map(dep => (
                          <Box key={dep.package} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {dep.package}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              Current: {dep.currentVersion} | Upgrade Path: {dep.upgradePath.join(' -> ')}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No outdated dependencies to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Card elevation={6}>
                    <CardHeader title="Industry Standards (IaC) Issues" />
                    <CardContent>
                      {scanResults && scanResults.industry && scanResults.industry.length > 0 ? (
                        scanResults.industry.map(issue => (
                          <Box key={issue.id || issue.title} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {issue.title || "Unnamed Issue"}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {issue.message || "No details provided."}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No industry issues to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Container>
          </main>
        </div>
      </SnackbarProvider>
    </ThemeProvider>
  );
}

export default App;