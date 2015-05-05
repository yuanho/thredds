package ucar.nc2.ui.coverage2;

import ucar.ma2.DataType;
import ucar.nc2.constants.AxisType;
//import ucar.nc2.dataset.*;
//import ucar.nc2.ft.fmrc.GridDatasetInv;
//import ucar.nc2.ft.cover.Coverage;
//import ucar.nc2.ft.cover.CoverageCS;
//import ucar.nc2.ft.cover.CoverageDataset;
//import ucar.nc2.ft.cover.impl.CoverageDatasetImpl;
import ucar.nc2.ft2.coverage.grid.*;
import ucar.nc2.ui.dialog.NetcdfOutputChooser;
import ucar.nc2.ui.widget.*;
import ucar.nc2.ui.widget.PopupMenu;
//import ucar.unidata.geoloc.ProjectionImpl;
import ucar.unidata.util.Format;
import ucar.util.prefs.PreferencesExt;
import ucar.util.prefs.ui.BeanTable;

import javax.swing.*;
//import java.awt.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.util.*;
import java.util.List;

/**
 * Description
 *
 * @author John
 * @since 12/25/12
 */
public class CoverageTable extends JPanel {
  private PreferencesExt prefs;
  private GridCoverageDataset gridDataset;

  private BeanTable varTable, csTable, axisTable;
  private JSplitPane split = null, split2 = null;
  private TextHistoryPane infoTA;
  private IndependentWindow infoWindow;
  private NetcdfOutputChooser outChooser;

  public CoverageTable(PreferencesExt prefs) {
    this.prefs = prefs;

    varTable = new BeanTable(GridBean.class, (PreferencesExt) prefs.node("GeogridBeans"), false);
    JTable jtable = varTable.getJTable();

    PopupMenu csPopup = new ucar.nc2.ui.widget.PopupMenu(jtable, "Options");
    csPopup.addAction("Show Declaration", new AbstractAction() {
      public void actionPerformed(ActionEvent e) {
        GridBean vb = (GridBean) varTable.getSelectedBean();
        //Variable v = vb.geogrid.getVariable();
        infoTA.clear();
        infoTA.appendLine("Coverage " + vb.geogrid.getName() + " :");
        infoTA.appendLine(vb.geogrid.toString());
        infoTA.gotoTop();
        infoWindow.show();
      }
    });

    /* csPopup.addAction("Show Coordinates", new AbstractAction() {
      public void actionPerformed(ActionEvent e) {
        CoverageBean vb = (CoverageBean) varTable.getSelectedBean();
        Formatter f = new Formatter();
        showCoordinates(vb, f);
        infoTA.setText(f.toString());
        infoTA.gotoTop();
        infoWindow.show();
      }
    });  */

    /* csPopup.addAction("WCS DescribeCoverage", new AbstractAction() {
      public void actionPerformed(ActionEvent e) {
        GeoGridBean vb = (GeoGridBean) varTable.getSelectedBean();
        if (gridDataset.findGridDatatype(vb.getName()) != null) {
          List<String> coverageIdList = Collections.singletonList(vb.getName());
          try {
            DescribeCoverage descCov =
                    ((thredds.wcs.v1_0_0_1.DescribeCoverageBuilder)
                            thredds.wcs.v1_0_0_1.WcsRequestBuilder
                                    .newWcsRequestBuilder("1.0.0",
                                            thredds.wcs.Request.Operation.DescribeCoverage,
                                            gridDataset, ""))
                            .setCoverageIdList(coverageIdList)
                            .buildDescribeCoverage();
            String dc = descCov.writeDescribeCoverageDocAsString();
            infoTA.clear();
            infoTA.appendLine(dc);
            infoTA.gotoTop();
            infoWindow.show();
          } catch (WcsException e1) {
            e1.printStackTrace();
          } catch (IOException e1) {
            e1.printStackTrace();
          }
        }
      }
    });  */

    // the info window
    infoTA = new TextHistoryPane();
    infoWindow = new IndependentWindow("Variable Information", BAMutil.getImage("netcdfUI"), infoTA);
    infoWindow.setBounds((Rectangle) prefs.getBean("InfoWindowBounds", new Rectangle(300, 300, 500, 300)));

    // show coordinate systems and axis
    csTable = new BeanTable(CoordSysBean.class, (PreferencesExt) prefs.node("GeoCoordinateSystemBean"), false);
    axisTable = new BeanTable(AxisBean.class, (PreferencesExt) prefs.node("GeoCoordinateAxisBean"), false);

    split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, false, varTable, csTable);
    split.setDividerLocation(prefs.getInt("splitPos", 500));

    split2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, false, split, axisTable);
    split2.setDividerLocation(prefs.getInt("splitPos2", 500));

    setLayout(new BorderLayout());
    add(split2, BorderLayout.CENTER);
  }

  /* public void addExtra(JPanel buttPanel, final FileManager fileChooser) {

    AbstractButton infoButton = BAMutil.makeButtcon("Information", "Parse Info", false);
    infoButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        if ((gridDataset != null) && (gridDataset instanceof ucar.nc2.dt.grid.GridDataset)) {
          ucar.nc2.dt.grid.GridDataset gdsImpl = (ucar.nc2.dt.grid.GridDataset) gridDataset;
          infoTA.clear();
          infoTA.appendLine(gdsImpl.getDetailInfo());
          infoTA.gotoTop();
          infoWindow.show();
        }
      }
    });
    buttPanel.add(infoButton);

    /* JButton wcsButton = new JButton("WCS");
    wcsButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        if (gridDataset != null) {
          URI gdUri = null;
          try {
            gdUri = new URI("http://none.such.server/thredds/wcs/dataset");
          } catch (URISyntaxException e1) {
            e1.printStackTrace();
            return;
          }
          GetCapabilities getCap =
                  ((thredds.wcs.v1_0_0_1.GetCapabilitiesBuilder)
                          thredds.wcs.v1_0_0_1.WcsRequestBuilder
                                  .newWcsRequestBuilder("1.0.0",
                                          thredds.wcs.Request.Operation.GetCapabilities,
                                          gridDataset, ""))
                          .setServerUri(gdUri)
                          .setSection(GetCapabilities.Section.All)
                          .buildGetCapabilities();
          try {
            String gc = getCap.writeCapabilitiesReportAsString();
            infoTA.setText(gc);
            infoTA.gotoTop();
            infoWindow.show();
          } catch (WcsException e1) {
            e1.printStackTrace();
          }
        }
      }
    });
    buttPanel.add(wcsButton);

    JButton invButton = new JButton("GridInv");
    invButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        if (gridDataset == null) return;
        if (!(gridDataset instanceof ucar.nc2.dt.grid.GridDataset)) return;
        GridDatasetInv inv = new GridDatasetInv((ucar.nc2.dt.grid.GridDataset) gridDataset, null);
        try {
          infoTA.setText(inv.writeXML(new Date()));
          infoTA.gotoTop();
          infoWindow.show();
        } catch (Exception e1) {
          e1.printStackTrace();
        }
      }
    });
    buttPanel.add(invButton);

    /* AbstractAction netcdfAction = new AbstractAction() {
      public void actionPerformed(ActionEvent e) {
        if (gridDataset == null) return;
        List<String> gridList = getSelectedGrids();
        if (gridList.size() == 0) {
          JOptionPane.showMessageDialog(CoverageTable.this, "No Grids are selected");
          return;
        }

        if (outChooser == null) {
          outChooser = new NetcdfOutputChooser((Frame) null);
          outChooser.addPropertyChangeListener("OK", new PropertyChangeListener() {
            public void propertyChange(PropertyChangeEvent evt) {
              writeNetcdf((NetcdfOutputChooser.Data) evt.getNewValue());
            }
          });
        }
        outChooser.setOutputFilename(gridDataset.getLocation());
        outChooser.setVisible(true);
      }
    };
    BAMutil.setActionProperties(netcdfAction, "netcdf", "Write netCDF-CF file", false, 'S', -1);
    BAMutil.addActionToContainer(buttPanel, netcdfAction);  */

    /*
 AbstractAction writeAction = new AbstractAction() {
   public void actionPerformed(ActionEvent e) {
     if (gridDataset == null) return;
     List<String> gridList = getSelectedGrids();
     if (gridList.size() == 0) {
       JOptionPane.showMessageDialog(GeoGridTable.this, "No Grids are selected");
       return;
     }
     String location = gridDataset.getLocationURI();
     if (location == null) location = "test";
     String suffix = (location.endsWith(".nc") ? ".sub.nc" : ".nc");
     int pos = location.lastIndexOf(".");
     if (pos > 0)
       location = location.substring(0, pos);

     String filename = fileChooser.chooseFilenameToSave(location + suffix);
     if (filename == null) return;

     try {
       NetcdfCFWriter.makeFileVersioned(filename, gridDataset, gridList, null, null);
       JOptionPane.showMessageDialog(GeoGridTable.this, "File successfully written");
     } catch (Exception ioe) {
       JOptionPane.showMessageDialog(GeoGridTable.this, "ERROR: " + ioe.getMessage());
       ioe.printStackTrace();
     }
   }
 };
 BAMutil.setActionProperties(writeAction, "netcdf", "Write netCDF-CF file", false, 'W', -1);
 BAMutil.addActionToContainer(buttPanel, writeAction);
  //; }

  private void showCoordinates(CoverageBean vb, Formatter f) {
    CoverageCS gcs = vb.geogrid.getCoordinateSystem();
    gcs.show(f, true);
  }

  /* private void writeNetcdf(NetcdfOutputChooser.Data data) {
    if (data.version == NetcdfFileWriter.Version.ncstream) return;

    try {
      NetcdfCFWriter.makeFileVersioned(data.outputFilename, gridDataset, getSelectedGrids(), null, null, data.version);
      JOptionPane.showMessageDialog(this, "File successfully written");
    } catch (Exception ioe) {
      JOptionPane.showMessageDialog(this, "ERROR: " + ioe.getMessage());
      ioe.printStackTrace();
    }
  } */

  public PreferencesExt getPrefs() {
    return prefs;
  }

  public void save() {
    varTable.saveState(false);
    prefs.putBeanObject("InfoWindowBounds", infoWindow.getBounds());
    if (split != null) prefs.putInt("splitPos", split.getDividerLocation());
    if (split2 != null) prefs.putInt("splitPos2", split2.getDividerLocation());
    if (csTable != null) csTable.saveState(false);
    if (axisTable != null) axisTable.saveState(false);
  }

  /* public void setDataset(NetcdfDataset ds, Formatter parseInfo) throws IOException {
    this.gridDataset = new CoverageDatasetImpl(ds, parseInfo);

    List<CoverageBean> beanList = new ArrayList<CoverageBean>();
    java.util.List<Coverage> list = gridDataset.getCoverages();
    for (Coverage g : list)
      beanList.add(new CoverageBean(g));
    varTable.setBeans(beanList);

    if (csTable != null) {
      List<CoverageCSBean> csList = new ArrayList<CoverageCSBean>();
      List<AxisBean> axisList;
      axisList = new ArrayList<AxisBean>();
      for (CoverageDataset.CoverageSet gset : gridDataset.getCoverageSets()) {
        csList.add(new CoverageCSBean(gset));
        CoverageCS gsys = gset.getCoverageCS();
        List<CoordinateAxis> axes = gsys.getCoordinateAxes();
        for (int i = 0; i < axes.size(); i++) {
          CoordinateAxis axis = axes.get(i);
          AxisBean axisBean = new AxisBean(axis);
          if (!contains(axisList, axisBean.getName()))
            axisList.add(axisBean);
        }
      }
      csTable.setBeans(csList);
      axisTable.setBeans(axisList);
    }
  }  */

  public void setDataset(GridCoverageDataset gds) throws IOException {
    this.gridDataset = gds;

    List<GridBean> beanList = new ArrayList<>();
    for (GridCoverage g : gridDataset.getGrids())
      beanList.add(new GridBean(g));
    varTable.setBeans(beanList);

    List<CoordSysBean> csList = new ArrayList<>();
    for (GridCoordSys gcs : gridDataset.getCoordSys())
      csList.add(new CoordSysBean(gcs));
    csTable.setBeans(csList);

    List<AxisBean> axisList = new ArrayList<>();
    for (GridCoordAxis axis : gridDataset.getCoordAxes())
      axisList.add(new AxisBean(axis));
    axisTable.setBeans(axisList);
  }

  private boolean contains(List<AxisBean> axisList, String name) {
    for (AxisBean axis : axisList)
      if (axis.getName().equals(name)) return true;
    return false;
  }

  public GridCoverageDataset getCoverageDataset() {
    return gridDataset;
  }

  public List<String> getSelectedGrids() {
    List grids = varTable.getSelectedBeans();
    List<String> result = new ArrayList<>();
    for (Object bean : grids) {
      GridBean gbean = (GridBean) bean;
      result.add(gbean.getName());
    }
    return result;
  }


  public GridCoverage getGrid() {
    GridBean vb = (GridBean) varTable.getSelectedBean();
    if (vb == null) {
      List<GridCoverage> grids = gridDataset.getGrids();
      if (grids.size() > 0)
        return grids.get(0);
      else
        return null;
    }
    return gridDataset.findCoverage(vb.getName());
  }

  public class GridBean {
    // static public String editableProperties() { return "title include logging freq"; }

    GridCoverage geogrid;
    String name, desc, units, coordSysName;
    DataType dataType;

    // no-arg constructor
    public GridBean() {
    }

    // create from a dataset
    public GridBean(GridCoverage geogrid) {
      this.geogrid = geogrid;
      setName(geogrid.getName());
      setDescription(geogrid.getDescription());
      setUnits(geogrid.getUnits());
      setDataType(geogrid.getDataType());
      setCoordSysName(geogrid.getCoordSysName());

      /* collect dimensions
      StringBuffer buff = new StringBuffer();
      java.util.List dims = geogrid.getDimensions();
      for (int j = 0; j < dims.size(); j++) {
        ucar.nc2.Dimension dim = (ucar.nc2.Dimension) dims.get(j);
        if (j > 0) buff.append(",");
        buff.append(dim.getLength());
      }
      setShape(buff.toString());

      CoverageCS gcs = geogrid.getCoordinateSystem();
      x = getAxisName(gcs.getXHorizAxis());
      y = getAxisName(gcs.getYHorizAxis());
      z = getAxisName(gcs.getVerticalAxis());
      t = getAxisName(gcs.getTimeAxis());

      Formatter f = new Formatter();
      List<ucar.nc2.Dimension> domain = gcs.getDomain();
      int count = 0;
      for (ucar.nc2.Dimension d : geogrid.getDimensions()) {
        if (!domain.contains(d)) {
          if (count++ > 0) f.format(",");
          f.format("%s",d.getShortName());
        }
      }
      extra = f.toString();  */
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getDescription() {
      return desc;
    }

    public void setDescription(String desc) {
      this.desc = desc;
    }

    public String getUnits() {
      return units;
    }

    public void setUnits(String units) {
      this.units = units;
    }

    public String getCoordSysName() {
      return coordSysName;
    }

    public void setCoordSysName(String coordSysName) {
      this.coordSysName = coordSysName;
    }

    public DataType getDataType() {
      return dataType;
    }

    public void setDataType(DataType dataType) {
      this.dataType = dataType;
    }
  }

  public class CoordSysBean {
    private GridCoordSys gcs;
    private String coordTrans, axisNames;

    // no-arg constructor
    public CoordSysBean() {
    }

    public CoordSysBean(GridCoordSys gcs) {
      this.gcs = gcs;

      Formatter buff = new Formatter();
      for (String ct : gcs.getTransformNames())
        buff.format("%s,", ct);
      setCoordTransforms(buff.toString());

      Formatter f = new Formatter();
      for (String ax : gcs.getAxisNames())
        f.format("%s,", ax);
      setAxisNames(f.toString());
    }

    public String getName() {
      return gcs.getName();
    }

    public int getNAxes() {
      return gcs.getAxisNames().size();
    }

    public String getAxisNames() {
      return axisNames;
    }

    public void setAxisNames(String axisNames) {
      this.axisNames = axisNames;
    }

    public String getCoordTransforms() {
      return coordTrans;
    }

    public void setCoordTransforms(String coordTrans) {
      this.coordTrans = coordTrans;
    }
  }

  public class AxisBean {
    GridCoordAxis axis;
    String name, desc, units;
    DataType dataType;
    AxisType axisType;
    long nvalues;
    boolean isRegular;
    double min, max, resolution;

    // no-arg constructor
    public AxisBean() {
    }

    // create from a dataset
    public AxisBean(GridCoordAxis v) {
      this.axis = v;

      setName(v.getName());
      setDataType(v.getDataType());
      setAxisType(v.getAxisType());
      setUnits(v.getUnits());
      setDescription(v.getDescription());
      setNvalues(v.getNvalues());
      setIsRegular(v.isRegular());
      setMin(v.getMin());
      setMax(v.getMax());
      setResolution(v.getResolution());

      /* collect dimensions
      StringBuffer lens = new StringBuffer();
      StringBuffer names = new StringBuffer();
      java.util.List dims = v.getDimensions();
      for (int j = 0; j < dims.size(); j++) {
        ucar.nc2.Dimension dim = (ucar.nc2.Dimension) dims.get(j);
        if (j > 0) {
          lens.append(",");
          names.append(",");
        }
        String name = dim.isShared() ? dim.getShortName() : "anon";
        names.append(name);
        lens.append(dim.getLength());
      }
      setDims(names.toString());
      setShape(lens.toString());

      AxisType at = v.getAxisType();
      if (at != null)
        setAxisType(at.toString());
      String p = v.getPositive();
      if (p != null)
        setPositive(p);

      if (v instanceof CoordinateAxis1D) {
        CoordinateAxis1D v1 = (CoordinateAxis1D) v;
        if (v1.isRegular())
          setRegular(Double.toString(v1.getIncrement()));
      } */
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getAxisType() {
      return axisType.name();
    }

    public void setAxisType(AxisType axisType) {
      this.axisType = axisType;
    }

    public String getDescription() {
      return desc;
    }

    public void setDescription(String desc) {
      this.desc = desc;
    }

    public String getUnits() {
      return units;
    }

    public void setUnits(String units) {
      this.units = (units == null) ? "null" : units;
    }

    public DataType getDataType() {
      return dataType;
    }

    public void setDataType(DataType dataType) {
      this.dataType = dataType;
    }

    public String getIsRegular() {
      return Boolean.toString(isRegular);
    }

    public void setIsRegular(boolean isRegular) {
      this.isRegular = isRegular;
    }

    public String getDesc() {
      return desc;
    }

    public void setDesc(String desc) {
      this.desc = desc;
    }

    public long getNvalues() {
      return nvalues;
    }

    public void setNvalues(long nvalues) {
      this.nvalues = nvalues;
    }

    public String getMin() {
      return String.format("%8.3f", min);
    }

    public void setMin(double min) {
      this.min = min;
    }

    public String getMax() {
      return String.format("%8.3f", max);
    }

    public void setMax(double max) {
      this.max = max;
    }

    public String getResolution() {
      return String.format("%8.3f", resolution);
    }

    public void setResolution(double resolution) {
      this.resolution = resolution;
    }
  }


  /**
   * Wrap this in a JDialog component.
   *
   * @param parent JFrame (application) or JApplet (applet) or null
   * @param title  dialog window title
   * @param modal  modal dialog or not
   * @return JDialog
   */
  public JDialog makeDialog(RootPaneContainer parent, String title, boolean modal) {
    return new Dialog(parent, title, modal);
  }

  private class Dialog extends JDialog {

    private Dialog(RootPaneContainer parent, String title, boolean modal) {
      super(parent instanceof Frame ? (Frame) parent : null, title, modal);

      // L&F may change
      UIManager.addPropertyChangeListener(new PropertyChangeListener() {
        public void propertyChange(PropertyChangeEvent e) {
          if (e.getPropertyName().equals("lookAndFeel"))
            SwingUtilities.updateComponentTreeUI(CoverageTable.Dialog.this);
        }
      });

      /* add a dismiss button
      JButton dismissButton = new JButton("Dismiss");
      buttPanel.add(dismissButton, null);

      dismissButton.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent evt) {
          setVisible(false);
        }
      }); */

      // add it to contentPane
      Container cp = getContentPane();
      cp.setLayout(new BorderLayout());
      cp.add(CoverageTable.this, BorderLayout.CENTER);
      pack();
    }
  }
}