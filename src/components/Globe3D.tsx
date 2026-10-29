import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
import { IpDetails, DnsResolver, Language, TestStatus } from '../types/network';
import { Shield, Globe as GlobeIcon, Radio, Maximize2, Minimize2, Compass, Sparkles, AlertTriangle, ShieldCheck } from 'lucide-react';

interface Globe3DProps {
  ipDetails: IpDetails | null;
  dnsResolvers: DnsResolver[];
  lang: Language;
  overallStatus: TestStatus;
}

// Convert Lat/Lon to 3D Cartesian coordinates on sphere
function latLonToVector3(lat: number, lon: number, radius: number): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

// Generate procedural Earth texture canvas
function createProceduralEarthTexture(isLeak: boolean): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 2048;
  canvas.height = 1024;
  const ctx = canvas.getContext('2d')!;

  // Deep Ocean Gradient (Reddish dark if leak, Cyber blue/dark if safe)
  const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
  if (isLeak) {
    gradient.addColorStop(0, '#1a0505');
    gradient.addColorStop(0.5, '#3b0707');
    gradient.addColorStop(1, '#0f0202');
  } else {
    gradient.addColorStop(0, '#040914');
    gradient.addColorStop(0.5, '#07162c');
    gradient.addColorStop(1, '#030712');
  }
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Cyber Grid Lines
  ctx.strokeStyle = isLeak ? '#501111' : '#0e2544';
  ctx.lineWidth = 1;
  for (let x = 0; x < canvas.width; x += 32) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  }
  for (let y = 0; y < canvas.height; y += 32) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }

  // Continent Landmass Dot Clusters
  ctx.fillStyle = isLeak ? '#801818' : '#0f4068';
  for (let i = 0; i < 8000; i++) {
    const rx = Math.random() * canvas.width;
    const ry = Math.random() * canvas.height;
    const size = Math.random() * 6 + 1.5;
    ctx.beginPath();
    ctx.arc(rx, ry, size, 0, Math.PI * 2);
    ctx.fill();
  }

  // Network Nodes
  ctx.fillStyle = isLeak ? '#ef4444' : '#06b6d4';
  for (let i = 0; i < 300; i++) {
    const rx = Math.random() * canvas.width;
    const ry = Math.random() * canvas.height;
    ctx.beginPath();
    ctx.arc(rx, ry, 2.5, 0, Math.PI * 2);
    ctx.fill();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

export const Globe3D: React.FC<Globe3DProps> = ({ ipDetails, dnsResolvers, lang, overallStatus }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [mode, setMode] = useState<'globe' | 'shield'>('globe');
  const isFa = lang === 'fa';

  const isLeak = overallStatus === 'LEAK_DETECTED' || overallStatus === 'WARNING';

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // Detect Software WebGL
    const isSoftwareGl = (() => {
      try {
        const gl = document.createElement('canvas').getContext('webgl2');
        if (!gl) return true;
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
        const gpu = String(gl.getParameter(param));
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
      } catch (e) {
        return false;
      }
    })();

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 450;

    // Colors
    const primaryColorHex = isLeak ? 0xef4444 : 0x10b981; // Red Alarm vs Green Secure
    const accentColorHex = isLeak ? 0xf87171 : 0x34d399;

    // Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(isLeak ? '#110404' : '#030712');
    scene.fog = new THREE.FogExp2(isLeak ? '#110404' : '#030712', 0.035);

    // Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 1.2, 7.5);

    // Renderer
    const renderer = new THREE.WebGLRenderer({
      antialias: !isSoftwareGl,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;

    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
    container.appendChild(renderer.domElement);

    // Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = !isSoftwareGl;
    controls.dampingFactor = 0.05;
    controls.rotateSpeed = 0.8;
    controls.minDistance = 3.5;
    controls.maxDistance = 14;
    controls.autoRotate = true;
    controls.autoRotateSpeed = isLeak ? 1.8 : 0.8; // Faster rotation when in leak alarm mode

    // Environment Lighting
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    scene.environment = pmremGenerator.fromScene(new RoomEnvironment(), 0.04).texture;
    pmremGenerator.dispose();

    // Lighting Rig
    const keyLight = new THREE.DirectionalLight(primaryColorHex, 3.5);
    keyLight.position.set(6, 6, 6);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(accentColorHex, 2.5);
    rimLight.position.set(-6, -2, -6);
    scene.add(rimLight);

    const fillLight = new THREE.HemisphereLight(primaryColorHex, isLeak ? 0x200000 : 0x030712, 1.5);
    scene.add(fillLight);

    // Main 3D Model Group
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 3D Alarm Pulse Rings (Pulsing Orbiting Torus Geometry)
    const alarmRingGeom = new THREE.TorusGeometry(2.6, 0.03, 16, 64);
    const alarmRingMat = new THREE.MeshPhysicalMaterial({
      color: primaryColorHex,
      emissive: primaryColorHex,
      emissiveIntensity: isLeak ? 0.8 : 0.3,
      metalness: 0.9,
      roughness: 0.1,
    });
    const alarmRingMesh = new THREE.Mesh(alarmRingGeom, alarmRingMat);
    alarmRingMesh.rotation.x = Math.PI / 3;
    mainGroup.add(alarmRingMesh);

    if (mode === 'globe') {
      // BUILD 3D EARTH GLOBE
      const globeRadius = 2.2;
      const earthGeometry = new THREE.SphereGeometry(globeRadius, 64, 64);
      const earthTexture = createProceduralEarthTexture(isLeak);
      
      const earthMaterial = new THREE.MeshPhysicalMaterial({
        map: earthTexture,
        roughness: 0.35,
        metalness: 0.25,
        clearcoat: 0.4,
        clearcoatRoughness: 0.1,
        emissive: isLeak ? 0xef4444 : 0x000000,
        emissiveIntensity: isLeak ? 0.15 : 0.0,
      });

      const earthMesh = new THREE.Mesh(earthGeometry, earthMaterial);
      mainGroup.add(earthMesh);

      // Atmosphere Glow Layer (Pulsing Red or Green)
      const atmosphereGeom = new THREE.SphereGeometry(globeRadius * 1.08, 48, 48);
      const atmosphereMat = new THREE.MeshBasicMaterial({
        color: primaryColorHex,
        transparent: true,
        opacity: isLeak ? 0.25 : 0.15,
        side: THREE.BackSide,
      });
      const atmosphereMesh = new THREE.Mesh(atmosphereGeom, atmosphereMat);
      mainGroup.add(atmosphereMesh);

      // Particle Cloud
      const particleCount = 250;
      const particleGeom = new THREE.BufferGeometry();
      const particlePositions = new Float32Array(particleCount * 3);
      for (let i = 0; i < particleCount * 3; i += 3) {
        const u = Math.random();
        const v = Math.random();
        const theta = u * 2.0 * Math.PI;
        const phi = Math.acos(2.0 * v - 1.0);
        const r = globeRadius + 0.3 + Math.random() * 0.8;
        particlePositions[i] = r * Math.sin(phi) * Math.cos(theta);
        particlePositions[i + 1] = r * Math.sin(phi) * Math.sin(theta);
        particlePositions[i + 2] = r * Math.cos(phi);
      }
      particleGeom.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
      const particleMat = new THREE.PointsMaterial({
        color: primaryColorHex,
        size: 0.045,
        transparent: true,
        opacity: 0.85,
      });
      const particlePoints = new THREE.Points(particleGeom, particleMat);
      mainGroup.add(particlePoints);

      // Client Location Pin
      const clientLat = ipDetails?.lat || 35.6892;
      const clientLon = ipDetails?.lon || 51.3890;
      const clientPos = latLonToVector3(clientLat, clientLon, globeRadius + 0.05);

      const clientPinGroup = new THREE.Group();
      
      const pinStemGeom = new THREE.CylinderGeometry(0.025, 0.025, 0.38, 16);
      const pinStemMat = new THREE.MeshPhysicalMaterial({
        color: primaryColorHex,
        emissive: primaryColorHex,
        emissiveIntensity: 0.5,
        metalness: 0.9
      });
      const pinStem = new THREE.Mesh(pinStemGeom, pinStemMat);
      pinStem.position.y = 0.19;

      const pinHeadGeom = new THREE.SphereGeometry(0.09, 16, 16);
      const pinHeadMat = new THREE.MeshPhysicalMaterial({
        color: primaryColorHex,
        emissive: primaryColorHex,
        emissiveIntensity: 0.8,
        roughness: 0.1,
      });
      const pinHead = new THREE.Mesh(pinHeadGeom, pinHeadMat);
      pinHead.position.y = 0.38;

      clientPinGroup.add(pinStem);
      clientPinGroup.add(pinHead);
      clientPinGroup.position.copy(clientPos);
      clientPinGroup.lookAt(new THREE.Vector3(0, 0, 0));
      clientPinGroup.rotateX(Math.PI / 2);
      mainGroup.add(clientPinGroup);

    } else {
      // BUILD 3D HOLOGRAPHIC SECURITY SHIELD (Red Warning Alarm or Green Secure Shield)
      const shieldGroup = new THREE.Group();

      const shieldShape = new THREE.Shape();
      shieldShape.moveTo(0, 1.8);
      shieldShape.lineTo(1.4, 1.2);
      shieldShape.lineTo(1.4, -0.4);
      shieldShape.lineTo(0, -1.8);
      shieldShape.lineTo(-1.4, -0.4);
      shieldShape.lineTo(-1.4, 1.2);
      shieldShape.closePath();

      const extrudeSettings = { depth: 0.18, bevelEnabled: true, bevelSegments: 5, steps: 1, bevelSize: 0.08, bevelThickness: 0.08 };
      const shieldGeom = new THREE.ExtrudeGeometry(shieldShape, extrudeSettings);
      const shieldMat = new THREE.MeshPhysicalMaterial({
        color: primaryColorHex,
        emissive: primaryColorHex,
        emissiveIntensity: isLeak ? 0.6 : 0.2,
        metalness: 0.85,
        roughness: 0.15,
        clearcoat: 1.0,
      });
      const shieldMesh = new THREE.Mesh(shieldGeom, shieldMat);
      shieldMesh.position.z = -0.08;
      shieldGroup.add(shieldMesh);

      // Rotating Outer Ring
      const ringGeom = new THREE.TorusGeometry(2.1, 0.04, 16, 64);
      const ringMat = new THREE.MeshPhysicalMaterial({
        color: primaryColorHex,
        emissive: primaryColorHex,
        emissiveIntensity: 0.7,
        metalness: 0.95
      });
      const ringMesh = new THREE.Mesh(ringGeom, ringMat);
      ringMesh.position.z = 0;
      shieldGroup.add(ringMesh);

      mainGroup.add(shieldGroup);
    }

    // Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    function animate() {
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();
      controls.update();

      mainGroup.rotation.y += delta * (isLeak ? 0.4 : 0.18);
      alarmRingMesh.rotation.z += delta * 0.5;

      // Pulsing scale in alarm mode
      if (isLeak) {
        alarmRingMesh.scale.setScalar(1 + Math.sin(time * 6) * 0.08);
      }

      renderer.render(scene, camera);
      animationFrameId = requestAnimationFrame(animate);
    }

    animate();

    const handleResize = () => {
      if (!container) return;
      const newW = container.clientWidth;
      const newH = container.clientHeight;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
      controls.dispose();
      renderer.dispose();
    };
  }, [ipDetails, mode, overallStatus]);

  return (
    <div className={`relative bg-gradient-to-b ${isLeak ? 'from-rose-950/40 via-slate-950 to-slate-950 border-rose-800/80 shadow-[0_0_40px_rgba(239,68,68,0.2)]' : 'from-slate-900 to-slate-950 border-slate-800 shadow-2xl'} border rounded-3xl overflow-hidden transition-all duration-300 ${isExpanded ? 'h-[620px]' : 'h-[420px]'}`}>
      
      {/* WebGL 3D Canvas */}
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Dynamic 3D Alert Overlay Banner */}
      <div className="absolute top-4 right-4 left-4 flex items-center justify-between pointer-events-none z-20">
        
        {/* Dynamic Status Badge */}
        <div className={`flex items-center gap-2.5 backdrop-blur-md px-4 py-2 rounded-2xl border font-bold text-xs pointer-events-auto shadow-2xl ${
          isLeak 
            ? 'bg-rose-950/90 text-rose-200 border-rose-800/80 shadow-rose-900/50 animate-pulse' 
            : 'bg-emerald-950/90 text-emerald-200 border-emerald-800/80 shadow-emerald-900/50'
        }`}>
          {isLeak ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 animate-bounce" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          )}
          <span>
            {isLeak 
              ? (isFa ? 'اخطار سه بعدی: نشت اطلاعات در شبکه شناسایی شد!' : '3D RED ALARM: NETWORK LEAK DETECTED!') 
              : (isFa ? 'امنیت سه بعدی: اتصال ۱۰۰٪ امن و بدون نشت' : '3D GREEN SECURE: SAFE CONNECTION')}
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 pointer-events-auto">
          <div className="bg-slate-950/85 backdrop-blur-md p-1 rounded-2xl border border-slate-800 flex items-center gap-1 shadow-lg">
            <button
              onClick={() => setMode('globe')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                mode === 'globe' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <GlobeIcon className="w-3.5 h-3.5" />
              <span>{isFa ? 'کره زمین' : 'Globe'}</span>
            </button>

            <button
              onClick={() => setMode('shield')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                mode === 'shield' 
                  ? (isLeak ? 'bg-rose-500 text-slate-950 shadow-md' : 'bg-emerald-500 text-slate-950 shadow-md') 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>{isFa ? 'سپر ۳D' : '3D Shield'}</span>
            </button>
          </div>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="bg-slate-950/85 backdrop-blur-md text-slate-300 hover:text-white p-2 rounded-2xl border border-slate-800 transition-colors shadow-lg"
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Bottom Information Bar */}
      <div className="absolute bottom-4 right-4 left-4 flex items-center justify-between bg-slate-950/85 backdrop-blur-md px-4 py-2.5 rounded-2xl border border-slate-800 text-xs shadow-xl">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Radio className={`w-4 h-4 ${isLeak ? 'text-rose-400 animate-ping' : 'text-emerald-400 animate-pulse'}`} />
            <span className="text-slate-300 font-medium">{isFa ? 'وضعیت پایش سه بعدی:' : '3D Monitor:'}</span>
            <span className={`font-bold ${isLeak ? 'text-rose-400' : 'text-emerald-400'}`}>
              {isLeak ? (isFa ? 'هشدار نشت فعال' : 'Active Leak Warning') : (isFa ? 'شبکه کاملاً محافظت‌شده' : 'Fully Protected')}
            </span>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-slate-400 text-[11px]">
          <Compass className="w-3.5 h-3.5 text-cyan-400" />
          <span>{isFa ? 'برای چرخش ۳D ماوس را درگ کنید' : 'Drag to rotate 3D view'}</span>
        </div>
      </div>

    </div>
  );
};
