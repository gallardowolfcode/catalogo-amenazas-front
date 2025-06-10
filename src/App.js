import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { saveAs } from 'file-saver';
import SearchIcon from '@mui/icons-material/Search';
import {
  Container,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  ListItemText,
  Button,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  CircularProgress,
  Box,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
} from '@mui/material';

function App() {
  const [amenazas, setAmenazas] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [severidad, setSeveridad] = useState('');
  const [prioridad, setPrioridad] = useState('');
  const [tipoIncidente, setTipoIncidente] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [formData, setFormData] = useState({
    amenaza: '',
    tipo_incidente: '',
    severidad: '',
    prioridad: '',
    fuentes_deteccion: [],
  });
  const [formError, setFormError] = useState('');
  const severidadOptions = ['Crítica', 'Alta', 'Media', 'Baja'];
  const prioridadOptions = ['Crítica', 'Alta', 'Media', 'Baja'];
  const [tipoIncidenteOptions, setTipoIncidenteOptions] = useState(['Policy Violation / Data Exposure Risk', 'Software Supply Chain / Pipeline Compromise', 'Malware', 'Phishing', 'DDoS', 'Ransomware', 'Intrusión', 'Missconfiguration – IAM / Access Policy ', 'Ataques de red', 'Exfiltración de datos', 'Vulnerabilidades explotadas', 'Problemas con dispositivos y sistemas', 'Incidentes internos']);
  const [nuevoTipoIncidente, setNuevoTipoIncidente] = useState('');
  const [showNewTipoIncidenteInput, setShowNewTipoIncidenteInput] = useState(false);
  const [fuentesDeteccionOptions, setFuentesDeteccionOptions] = useState([
    'Firewall',
    'Antivirus',
    'SIEM',
    'IDS/IPS',
    'Logs del sistema',
    'Usuarios',
    'CSPM tools',
    'Cloud audit logs',
    'IAM policy scans',
    'Threat Intelligence',
    'Red Team findings',
    'Source Control Logs',
    'CI/CD Logs',
    'EDR',
    'SAST/DAST Tools',
    'Developer Reports',
    'Threat Intel Feeds',
  ]);
  const [nuevaFuente, setNuevaFuente] = useState('');
  const [showNewFuenteInput, setShowNewFuenteInput] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [editId, setEditId] = useState(null);
  const fetchAmenazas = () => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({
      skip: 0,
      limit: 100,
    });
    if (severidad) params.append('severidad', severidad);
    if (prioridad) params.append('prioridad', prioridad);
    if (tipoIncidente) params.append('tipo_incidente', tipoIncidente);
    if (searchTerm.trim() !== '') params.append('amenaza', searchTerm.trim());

    fetch(`https://catalogo-amenazas-back.onrender.com/threats?${params.toString()}`)
      .then((res) => {
        if (!res.ok) throw new Error('Error al obtener amenazas');
        return res.json();
      })
      .then((data) => {
        setAmenazas(data.items || []);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAmenazas();
  }, [severidad, prioridad, tipoIncidente]);

  const handleOpenDialog = () => {
    setFormData({
      amenaza: '',
      tipo_incidente: '',
      severidad: '',
      prioridad: '',
      fuentes_deteccion: [],
    });
    setFormError('');
    setShowNewTipoIncidenteInput(false);
    setNuevoTipoIncidente('');
    setEditId(null);
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setShowNewTipoIncidenteInput(false);
    setNuevoTipoIncidente('');
    setNuevaFuente('');
    setShowNewFuenteInput(false);
    setEditId(null);
  };

  const handleInputChange = (event) => {
    const { name, value } = event.target;

    if (name === 'fuentes_deteccion') {
      // Aquí value ya es un array con las opciones seleccionadas, solo seteamos
      setFormData((prev) => ({
        ...prev,
        fuentes_deteccion: value,
      }));
    } else {
      setFormData((prev) => ({
        ...prev,
        [name]: value,
      }));
    }
  };


  const handleSubmit = async () => {

    if (showNewTipoIncidenteInput && nuevoTipoIncidente.trim() && !tipoIncidenteOptions.includes(nuevoTipoIncidente)) {
      setTipoIncidente(prev => [...prev, nuevoTipoIncidente]);
    }
    if (editId && !window.confirm("¿Estás seguro de guardar los cambios?")) return;


    // Paso 1: verificar si hay una nueva fuente y agregarla si no existe
    if (showNewFuenteInput && nuevaFuente.trim()) {
      const nuevasFuentes = nuevaFuente
        .split(',')
        .map(f => f.trim())
        .filter(f => f !== '');

      // Agregar sólo las que no existan en opciones
      const nuevasUnicas = nuevasFuentes.filter(f => !fuentesDeteccionOptions.includes(f));

      if (nuevasUnicas.length > 0) {
        setFuentesDeteccionOptions(prev => [...prev, ...nuevasUnicas]);
      }

      // Actualizar fuentes seleccionadas en el formulario, sin duplicados
      setFormData(prev => {
        const seleccionadasSet = new Set(prev.fuentes_deteccion);
        nuevasUnicas.forEach(f => seleccionadasSet.add(f));
        return {
          ...prev,
          fuentes_deteccion: Array.from(seleccionadasSet),
        };
      });
    }


    // Validar campos obligatorios
    const tipoIncidenteFinal = showNewTipoIncidenteInput && nuevoTipoIncidente
      ? nuevoTipoIncidente
      : formData.tipo_incidente;

    if (!formData.amenaza || !tipoIncidenteFinal || !formData.severidad || !formData.prioridad) {
      setFormError('Por favor, completa todos los campos requeridos.');
      return;
    }

    const dataToSend = {
      ...formData,
      tipo_incidente: tipoIncidenteFinal,
    };

    try {
      if (editId) {
        await axios.put(`http://localhost:8000/threats/${editId}`, dataToSend);
      } else {
        await axios.post('http://localhost:8000/threats', dataToSend);
      }
      setOpenDialog(false);
      setEditId(null);
      fetchAmenazas();
    } catch (error) {
      setFormError('Error al guardar la amenaza.');
      console.error(error);
    }
  };


  const handleEditClick = (amenaza) => {
    setEditId(amenaza.id);
    setFormData({
      amenaza: amenaza.amenaza,
      tipo_incidente: amenaza.tipo_incidente,
      severidad: amenaza.severidad,
      prioridad: amenaza.prioridad,
      fuentes_deteccion: amenaza.fuentes_deteccion || [],
    });
    setFormError('');
    setShowNewTipoIncidenteInput(false);
    setNuevoTipoIncidente('');
    setOpenDialog(true);
  };

  const handleDeleteClick = async (id) => {
    if (!window.confirm('¿Estás seguro de eliminar esta amenaza?')) return;

    try {
      await axios.delete(`http://localhost:8000/threats/${id}`);
      fetchAmenazas();
    } catch (error) {
      alert('Error al eliminar la amenaza.');
      console.error(error);
    }
  };

  const eliminarFuente = (fuenteAEliminar) => {
    setFormData(prev => ({
      ...prev,
      fuentes_deteccion: prev.fuentes_deteccion.filter(f => f !== fuenteAEliminar),
    }));
  };

  const modificarFuente = (fuenteOriginal, fuenteNueva) => {
    if (fuentesDeteccionOptions.includes(fuenteNueva)) {
      alert("Esta fuente ya existe.");
      return;
    }

    setFormData(prev => ({
      ...prev,
      fuentes_deteccion: prev.fuentes_deteccion.map(f =>
        f === fuenteOriginal ? fuenteNueva : f
      ),
    }));

    setFuentesDeteccionOptions(prev =>
      prev.map(f => (f === fuenteOriginal ? fuenteNueva : f))
    );
  };


  const exportToCSV = () => {
    if (amenazas.length === 0) {
      alert('No hay datos para exportar');
      return;
    }

    const headers = ['Amenaza', 'Tipo de Incidente', 'Severidad', 'Prioridad', 'Fuentes de Detección'];
    const rows = amenazas.map((a) => [
      a.amenaza,
      a.tipo_incidente,
      a.severidad,
      a.prioridad,
      (a.fuentes_deteccion || []).join(', '),
    ]);

    const csvContent =
      [headers, ...rows]
        .map((e) =>
          e
            .map((field) => `"${(field ?? '').toString().replace(/"/g, '""')}"`)
            .join(',')
        )
        .join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    saveAs(blob, 'amenazas_export.csv');
  };

  return (
    <Container sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Catálogo de Amenazas
      </Typography>

      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2, alignItems: 'center' }}>
        <FormControl sx={{ flexGrow: 1, minWidth: 200 }}>
          <TextField
            label="Buscar por amenaza"
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') fetchAmenazas();
            }}
            InputProps={{
              endAdornment: (
                <Button onClick={fetchAmenazas} size="small" sx={{ ml: 1 }}>
                  <SearchIcon />
                </Button>
              ),
            }}
          />
        </FormControl>

        <FormControl sx={{ minWidth: 150 }}>
          <InputLabel>Severidad</InputLabel>
          <Select
            value={severidad}
            label="Severidad"
            onChange={(e) => setSeveridad(e.target.value)}
          >
            <MenuItem value="">Todas</MenuItem>
            {severidadOptions.map((opt) => (
              <MenuItem key={opt} value={opt}>
                {opt}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 150 }}>
          <InputLabel>Prioridad</InputLabel>
          <Select
            value={prioridad}
            label="Prioridad"
            onChange={(e) => setPrioridad(e.target.value)}
          >
            <MenuItem value="">Todas</MenuItem>
            {prioridadOptions.map((opt) => (
              <MenuItem key={opt} value={opt}>
                {opt}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 200 }}>
          <InputLabel>Tipo de Incidente</InputLabel>
          <Select
            value={tipoIncidente}
            label="Tipo de Incidente"
            onChange={(e) => setTipoIncidente(e.target.value)}
          >
            <MenuItem value="">Todos</MenuItem>
            {tipoIncidenteOptions.map((opt) => (
              <MenuItem key={opt} value={opt}>
                {opt}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <Button variant="contained" onClick={fetchAmenazas}>
          Buscar
        </Button>

        <Button variant="outlined" color="primary" onClick={handleOpenDialog}>
          Nueva Amenaza
        </Button>

        <Button variant="outlined" color="secondary" onClick={exportToCSV}>
          Exportar CSV
        </Button>
      </Box>

      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
          <CircularProgress />
        </Box>
      )}

      {error && (
        <Typography color="error" sx={{ my: 2 }}>
          {error}
        </Typography>
      )}

      {!loading && !error && amenazas.length === 0 && (
        <Typography sx={{ my: 2 }}>No se encontraron amenazas.</Typography>
      )}

      {amenazas.length > 0 && (
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Amenaza</TableCell>
              <TableCell>Tipo de Incidente</TableCell>
              <TableCell>Severidad</TableCell>
              <TableCell>Prioridad</TableCell>
              <TableCell>Fuentes de Detección</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {amenazas.map((a) => (
              <TableRow key={a.id}>
                <TableCell>{a.amenaza}</TableCell>
                <TableCell>{a.tipo_incidente}</TableCell>
                <TableCell>{a.severidad}</TableCell>
                <TableCell>{a.prioridad}</TableCell>
                <TableCell>{(a.fuentes_deteccion || []).join(', ')}</TableCell>
                <TableCell>
                  <Button
                    variant="outlined"
                    color="primary"
                    size="small"
                    sx={{ mr: 1 }}
                    onClick={() => handleEditClick(a)}
                  >
                    Modificar
                  </Button>
                  <Button
                    variant="outlined"
                    color="error"
                    size="small"
                    onClick={() => handleDeleteClick(a.id)}
                  >
                    Eliminar
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={openDialog} onClose={handleCloseDialog} fullWidth maxWidth="sm">
        <DialogTitle>{editId ? 'Modificar Amenaza' : 'Nueva Amenaza'}</DialogTitle>
        <DialogContent dividers>
          {formError && (
            <Typography color="error" sx={{ mb: 2 }}>
              {formError}
            </Typography>
          )}
          <TextField
            fullWidth
            margin="dense"
            label="Amenaza"
            name="amenaza"
            value={formData.amenaza}
            onChange={handleInputChange}
          />

          <FormControl fullWidth margin="dense">
            <InputLabel>Tipo de Incidente</InputLabel>
            <Select
              name="tipo_incidente"
              value={formData.tipo_incidente}
              onChange={(e) => {
                if (e.target.value === '__nuevo__') {
                  setShowNewTipoIncidenteInput(true);
                  setFormData((prev) => ({ ...prev, tipo_incidente: '' }));
                  setNuevoTipoIncidente('');
                } else {
                  setFormData((prev) => ({ ...prev, tipo_incidente: e.target.value }));
                  setShowNewTipoIncidenteInput(false);
                  setNuevoTipoIncidente('');
                }
              }}
              label="Tipo de Incidente"
            >
              {tipoIncidenteOptions.map((opt) => (
                <MenuItem key={opt} value={opt}>
                  {opt}
                </MenuItem>
              ))}
              <MenuItem value="__nuevo__">
                <em>Agregar nuevo...</em>
              </MenuItem>
            </Select>
            {showNewTipoIncidenteInput && (
              <TextField
                margin="dense"
                label="Nuevo tipo de incidente (usa comas para varios)"
                fullWidth
                value={nuevoTipoIncidente}
                onChange={(e) => setNuevoTipoIncidente(e.target.value)}
                onBlur={() => {
                  const nuevosTipos = nuevoTipoIncidente
                    .split(',')
                    .map((item) => item.trim())
                    .filter((item) => item !== '' && !tipoIncidenteOptions.includes(item));

                  if (nuevosTipos.length > 0) {
                    setTipoIncidenteOptions((prev) => [...prev, ...nuevosTipos]);
                    setFormData((prev) => ({ ...prev, tipo_incidente: nuevosTipos[0] }));
                  }

                  setNuevoTipoIncidente('');
                  setShowNewTipoIncidenteInput(false);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault(); // Evita que se envíe el formulario
                    e.target.blur();    // Dispara onBlur para procesar entrada
                  }
                }}
              />
            )}

          </FormControl>

          <FormControl fullWidth margin="dense">
            <InputLabel>Severidad</InputLabel>
            <Select
              name="severidad"
              value={formData.severidad}
              onChange={handleInputChange}
              label="Severidad"
            >
              {severidadOptions.map((opt) => (
                <MenuItem key={opt} value={opt}>
                  {opt}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth margin="dense">
            <InputLabel>Prioridad</InputLabel>
            <Select
              name="prioridad"
              value={formData.prioridad}
              onChange={handleInputChange}
              label="Prioridad"
            >
              {prioridadOptions.map((opt) => (
                <MenuItem key={opt} value={opt}>
                  {opt}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth margin="dense">
            <InputLabel>Fuentes de Detección</InputLabel>
            <Select
              multiple
              name="fuentes_deteccion"
              value={formData.fuentes_deteccion}
              onChange={handleInputChange}
              renderValue={(selected) => selected.join(', ')}
            >
              {fuentesDeteccionOptions.map((fuente) => (
                <MenuItem key={fuente} value={fuente}>
                  <Checkbox checked={formData.fuentes_deteccion.includes(fuente)} />
                  <ListItemText primary={fuente} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <Box sx={{ mt: 1 }}>
            <Button
              onClick={() => setShowNewFuenteInput(!showNewFuenteInput)}
              size="small"
            >
              {showNewFuenteInput ? 'Ocultar nueva fuente' : 'Agregar nueva fuente'}
            </Button>
            {showNewFuenteInput && (
              <TextField
                margin="dense"
                fullWidth
                label="Nueva fuente (separadas por coma)"
                value={nuevaFuente}
                onChange={(e) => setNuevaFuente(e.target.value)}
              />
            )}
          </Box>
        </DialogContent>

        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancelar</Button>
          <Button onClick={handleSubmit} variant="contained" color="primary">
            {editId ? 'Guardar cambios' : 'Guardar'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default App;
