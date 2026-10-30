import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
import { IpDetails, DnsResolver, Language, TestStatus } from '../types/network';
import {
  GlobeVisualCategory,
  isValidGeoCoordinate,
  resolveGlobeVisualStatus,
} from '../utils/networkEvaluator';
import {
  Shield,
  Globe as GlobeIcon,
  Radio,
  Maximize2,
  Minimize2,
  Compass,
  AlertTriangle,
  AlertOctagon,
  ShieldCheck,
  HelpCircle,
  MonitorOff,
} from 'lucide-react';

export interface Globe3DProps {
  ipDetails: IpDetails | null;
  dnsResolvers?: DnsResolver[];
  lang: Language;
  overallStatus: TestStatus;
}

const ORIGIN_VECTOR = new THREE.Vector3(0, 0, 0);

/**
 * Converts valid finite Lat/Lon (lat in [-90, 90], lon in [-180, 180]) to 3D Cartesian coordinates on a sphere.
 * Returns null for any invalid or out-of-range coordinate so no invalid pin can ever be plotted.
 */
export function latLonToVector3(
  lat: unknown,
  lon: unknown,
  radius: number
): THREE.Vector3 | null {
  if (!isValidGeoCoordinate(lat, lon) || !Number.isFinite(radius) || radius <= 0) {
    return null;
  }
  const numericLat = lat as number;
  const numericLon = lon as number;
  const phi = (90 - numericLat) * (Math.PI / 180);
  const theta = (numericLon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

export interface DisposableLike {
  dispose: () => void;
}

/**
 * Tracks all Three.js resources created by Globe3D and guarantees safe, deduplicated disposal
 * in useEffect cleanup without double-freeing shared geometries, materials, or textures.
 */
export function createGlobeResourceManager() {
  const geometries = new Set< DisposableLike >();
  const materials = new Set< DisposableLike >();
  const textures = new Set< DisposableLike >();
  const renderTargets = new Set< DisposableLike >();
  const disposedObjects = new WeakSet<object>();

  let isDisposed = false;

  const safeDisposeOnce = (item: DisposableLike | null | undefined) => {
    if (!item || typeof item !== 'object') return false;
    if (disposedObjects.has(item)) return false;
    disposedObjects.add(item);
    try {
      item.dispose();
      return true;
    } catch {
      return false;
    }
  };

  return {
    get isDisposed() {
      return isDisposed;
    },
    trackGeometry<T extends DisposableLike>(geom: T): T {
      geometries.add(geom);
      return geom;
    },
    trackMaterial<T extends DisposableLike>(mat: T): T {
      materials.add(mat);
      return mat;
    },
    trackTexture<T extends DisposableLike>(tex: T): T {
      textures.add(tex);
      return tex;
    },
    trackRenderTarget<T extends DisposableLike>(rt: T): T {
      renderTargets.add(rt);
      return rt;
    },
    collectFromScene(root: THREE.Object3D) {
      root.traverse(obj => {
        const mesh = obj as THREE.Mesh;
        if (mesh.geometry && typeof mesh.geometry.dispose === 'function') {
          geometries.add(mesh.geometry);
        }
        const registerMat = (m: unknown) => {
          if (m && typeof m === 'object' && 'dispose' in m && typeof (m as DisposableLike).dispose === 'function') {
            materials.add(m as DisposableLike);
            const matRecord = m as Record<string, unknown>;
            if (
              matRecord.map &&
              typeof matRecord.map === 'object' &&
              'dispose' in matRecord.map &&
              typeof (matRecord.map as DisposableLike).dispose === 'function'
            ) {
              textures.add(matRecord.map as DisposableLike);
            }
          }
        };
        if (Array.isArray(mesh.material)) {
          mesh.material.forEach(registerMat);
        } else if (mesh.material) {
          registerMat(mesh.material);
        }
      });
    },
    disposeAll(extras?: {
      animationFrameId?: number | null;
      timeoutId?: ReturnType<typeof setTimeout> | null;
      resizeObserver?: { disconnect: () => void } | null;
      controls?: DisposableLike | null;
      pmremGenerator?: DisposableLike | null;
      roomEnvironment?: DisposableLike | null;
      renderer?: (DisposableLike & { domElement?: Node | null }) | null;
      container?: Node | null;
      cancelFrame?: (id: number) => void;
      clearTimer?: (id: ReturnType<typeof setTimeout>) => void;
    }) {
      if (isDisposed) return;
      isDisposed = true;
      const cancelFrameFn =
        extras?.cancelFrame ||
        (typeof cancelAnimationFrame === 'function' ? cancelAnimationFrame : undefined);
      const clearTimerFn =
        extras?.clearTimer || (typeof clearTimeout === 'function' ? clearTimeout : undefined);

      if (extras?.animationFrameId != null && cancelFrameFn) {
        cancelFrameFn(extras.animationFrameId);
      }
      if (extras?.timeoutId != null && clearTimerFn) {
        clearTimerFn(extras.timeoutId);
      }
      if (extras?.resizeObserver) {
        try {
          extras.resizeObserver.disconnect();
        } catch {
          // Ignore disconnect errors
        }
      }
      safeDisposeOnce(extras?.controls);
      safeDisposeOnce(extras?.pmremGenerator);
      safeDisposeOnce(extras?.roomEnvironment);

      renderTargets.forEach(rt => safeDisposeOnce(rt));
      renderTargets.clear();

      textures.forEach(tex => safeDisposeOnce(tex));
      textures.clear();

      materials.forEach(mat => safeDisposeOnce(mat));
      materials.clear();

      geometries.forEach(geom => safeDisposeOnce(geom));
      geometries.clear();

      if (extras?.renderer) {
        const domElem = extras.renderer.domElement;
        safeDisposeOnce(extras.renderer);
        if (domElem && extras.container && domElem.parentNode === extras.container) {
          try {
            extras.container.removeChild(domElem);
          } catch {
            // Ignore DOM removal errors
          }
        }
      }
    },
  };
}

/**
 * Safely probes WebGL availability and initializes WebGLRenderer without throwing when WebGL is disabled or GPU fails.
 */
export function initGlobeWebGLSafe<
  TRenderer extends DisposableLike & { getContext: () => unknown } = THREE.WebGLRenderer
>(options?: {
  probeContext?: () => { gl: WebGLRenderingContext | null; gpuRenderer: string } | null;
  createRenderer?: (params: {
    antialias: boolean;
    powerPreference: 'low-power' | 'high-performance';
  }) => TRenderer;
  hardwareConcurrency?: number;
}): {
  renderer: TRenderer | null;
  webglUnavailable: boolean;
  isLowPowerOrSoftwareGl: boolean;
} {
  let isLowPowerOrSoftwareGl = false;

  try {
    if (options?.probeContext) {
      const probeResult = options.probeContext();
      if (!probeResult || !probeResult.gl) {
        return {
          renderer: null,
          webglUnavailable: true,
          isLowPowerOrSoftwareGl: true,
        };
      }
      const cores = options.hardwareConcurrency ?? 4;
      isLowPowerOrSoftwareGl =
        cores <= 2 ||
        /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(
          probeResult.gpuRenderer || ''
        );
    } else {
      const probeCanvas = document.createElement('canvas');
      const gl =
        probeCanvas.getContext('webgl2') ||
        probeCanvas.getContext('webgl') ||
        probeCanvas.getContext('experimental-webgl');
      if (!gl) {
        return {
          renderer: null,
          webglUnavailable: true,
          isLowPowerOrSoftwareGl: true,
        };
      }
      const webglCtx = gl as WebGLRenderingContext;
      const ext = webglCtx.getExtension('WEBGL_debug_renderer_info');
      const param = ext ? ext.UNMASKED_RENDERER_WEBGL : webglCtx.RENDERER;
      const gpu = String(webglCtx.getParameter(param) || '');
      webglCtx.getExtension('WEBGL_lose_context')?.loseContext();
      const cores =
        options?.hardwareConcurrency ??
        (typeof navigator !== 'undefined' &&
        typeof navigator.hardwareConcurrency === 'number'
          ? navigator.hardwareConcurrency
          : 4);
      isLowPowerOrSoftwareGl =
        cores <= 2 ||
        /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
    }
  } catch {
    isLowPowerOrSoftwareGl = true;
  }

  try {
    const factory =
      options?.createRenderer ??
      (params => new THREE.WebGLRenderer(params) as unknown as TRenderer);
    const renderer = factory({
      antialias: !isLowPowerOrSoftwareGl,
      powerPreference: isLowPowerOrSoftwareGl ? 'low-power' : 'high-performance',
    });
    if (!renderer || !renderer.getContext()) {
      renderer?.dispose?.();
      return {
        renderer: null,
        webglUnavailable: true,
        isLowPowerOrSoftwareGl,
      };
    }
    return {
      renderer,
      webglUnavailable: false,
      isLowPowerOrSoftwareGl,
    };
  } catch {
    return {
      renderer: null,
      webglUnavailable: true,
      isLowPowerOrSoftwareGl,
    };
  }
}

// Generate procedural Earth texture canvas (purely decorative graphical representation)
function createProceduralEarthTexture(
  visualState: GlobeVisualCategory
): THREE.CanvasTexture | null {
  if (typeof document === 'undefined') return null;
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
  if (visualState === 'leak') {
    gradient.addColorStop(0, '#1a0505');
    gradient.addColorStop(0.5, '#3b0707');
    gradient.addColorStop(1, '#0f0202');
  } else if (visualState === 'error') {
    gradient.addColorStop(0, '#190d07');
    gradient.addColorStop(0.5, '#2d160b');
    gradient.addColorStop(1, '#0f0704');
  } else if (visualState === 'inconclusive') {
    gradient.addColorStop(0, '#171305');
    gradient.addColorStop(0.5, '#292007');
    gradient.addColorStop(1, '#0c0a03');
  } else {
    gradient.addColorStop(0, '#040914');
    gradient.addColorStop(0.5, '#07162c');
    gradient.addColorStop(1, '#030712');
  }
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Decorative Cyber Grid Lines
  ctx.strokeStyle =
    visualState === 'leak'
      ? '#501111'
      : visualState === 'error'
      ? '#4c2412'
      : visualState === 'inconclusive'
      ? '#42330d'
      : '#0e2544';
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

  // Deterministic decorative dot pattern (strictly visual texture, never represents network nodes)
  ctx.fillStyle =
    visualState === 'leak'
      ? '#801818'
      : visualState === 'error'
      ? '#7c3a1d'
      : visualState === 'inconclusive'
      ? '#785c12'
      : '#0f4068';
  for (let i = 0; i < 2500; i++) {
    const seed = (i * 9301 + 49297) % 233280;
    const seed2 = (i * 49297 + 9301) % 233280;
    const rx = (seed / 233280) * canvas.width;
    const ry = (seed2 / 233280) * canvas.height;
    const size = (i % 5) + 1.5;
    ctx.beginPath();
    ctx.arc(rx, ry, size, 0, Math.PI * 2);
    ctx.fill();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

export const Globe3D: React.FC<Globe3DProps> = ({
  ipDetails,
  dnsResolvers: _dnsResolvers,
  lang,
  overallStatus,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [mode, setMode] = useState<'globe' | 'shield'>('globe');
  const [webglUnavailable, setWebglUnavailable] = useState(false);
  const isFa = lang === 'fa';

  const statusInfo = resolveGlobeVisualStatus(overallStatus, ipDetails);
  const { visualCategory, isLeak, isError, isPass } = statusInfo;

  const validLat = ipDetails?.lat;
  const validLon = ipDetails?.lon;
  const hasValidCoordinates =
    ipDetails !== null && isValidGeoCoordinate(validLat, validLon);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return undefined;

    const resourceManager = createGlobeResourceManager();

    const initResult = initGlobeWebGLSafe();
    if (initResult.webglUnavailable || !initResult.renderer) {
      setWebglUnavailable(true);
      resourceManager.disposeAll({ container });
      return undefined;
    }

    setWebglUnavailable(false);
    const renderer = initResult.renderer;
    const { isLowPowerOrSoftwareGl } = initResult;

    let controls: OrbitControls | null = null;
    let roomEnvironment: RoomEnvironment | null = null;
    let pmremGenerator: THREE.PMREMGenerator | null = null;
    let resizeObserver: ResizeObserver | null = null;
    let animationFrameId: number | null = null;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    let lastWidth = Math.max(1, container.clientWidth || 800);
    let lastHeight = Math.max(1, container.clientHeight || 420);

    renderer.setSize(lastWidth, lastHeight, false);
    renderer.setPixelRatio(
      isLowPowerOrSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2)
    );
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;

    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
    container.appendChild(renderer.domElement);

    // Colors based on strict 4-category model (leak, error, pass, inconclusive)
    const primaryColorHex = isLeak
      ? 0xef4444
      : isError
      ? 0xf97316
      : isPass
      ? 0x10b981
      : 0xf59e0b;
    const accentColorHex = isLeak
      ? 0xf87171
      : isError
      ? 0xfb923c
      : isPass
      ? 0x34d399
      : 0xfbbf24;
    const bgHex = isLeak ? '#110404' : isError ? '#120804' : '#030712';

    // Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(bgHex);
    scene.fog = new THREE.FogExp2(bgHex, 0.035);

    // Camera
    const camera = new THREE.PerspectiveCamera(45, lastWidth / lastHeight, 0.1, 100);
    camera.position.set(0, 1.2, 7.5);

    // Controls
    controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = !isLowPowerOrSoftwareGl;
    controls.dampingFactor = 0.05;
    controls.rotateSpeed = 0.8;
    controls.minDistance = 3.5;
    controls.maxDistance = 14;
    controls.autoRotate = !isLowPowerOrSoftwareGl;
    controls.autoRotateSpeed = isLeak ? 1.5 : 0.7;

    // Environment Lighting (skip expensive PMREM generation on software/low-end WebGL)
    if (!isLowPowerOrSoftwareGl) {
      try {
        pmremGenerator = new THREE.PMREMGenerator(renderer);
        roomEnvironment = new RoomEnvironment();
        const envTarget = resourceManager.trackRenderTarget(
          pmremGenerator.fromScene(roomEnvironment, 0.04)
        );
        resourceManager.trackTexture(envTarget.texture);
        scene.environment = envTarget.texture;
        pmremGenerator.dispose();
        pmremGenerator = null;
        roomEnvironment.dispose();
        roomEnvironment = null;
      } catch {
        // Fallback to direct lights if PMREM fails
      }
    }

    // Lighting Rig
    const keyLight = new THREE.DirectionalLight(primaryColorHex, 3.5);
    keyLight.position.set(6, 6, 6);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(accentColorHex, 2.5);
    rimLight.position.set(-6, -2, -6);
    scene.add(rimLight);

    const fillLight = new THREE.HemisphereLight(
      primaryColorHex,
      isLeak ? 0x200000 : isError ? 0x1f0d05 : 0x030712,
      1.5
    );
    scene.add(fillLight);

    // Main 3D Model Group
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 3D Status Ring
    const alarmRingGeom = resourceManager.trackGeometry(
      new THREE.TorusGeometry(2.6, 0.03, 16, 64)
    );
    const alarmRingMat = resourceManager.trackMaterial(
      new THREE.MeshPhysicalMaterial({
        color: primaryColorHex,
        emissive: primaryColorHex,
        emissiveIntensity: isLeak ? 0.8 : isError ? 0.45 : 0.3,
        metalness: 0.9,
        roughness: 0.1,
      })
    );
    const alarmRingMesh = new THREE.Mesh(alarmRingGeom, alarmRingMat);
    alarmRingMesh.rotation.x = Math.PI / 3;
    mainGroup.add(alarmRingMesh);

    if (mode === 'globe') {
      const globeRadius = 2.2;
      const segments = isLowPowerOrSoftwareGl ? 24 : 48;
      const earthGeometry = resourceManager.trackGeometry(
        new THREE.SphereGeometry(globeRadius, segments, segments)
      );
      const earthTexture = createProceduralEarthTexture(visualCategory);
      if (earthTexture) {
        resourceManager.trackTexture(earthTexture);
      }

      const earthMaterial = resourceManager.trackMaterial(
        new THREE.MeshPhysicalMaterial({
          map: earthTexture,
          roughness: 0.35,
          metalness: 0.25,
          clearcoat: 0.4,
          clearcoatRoughness: 0.1,
          emissive: isLeak ? 0xef4444 : isError ? 0xf97316 : 0x000000,
          emissiveIntensity: isLeak ? 0.15 : isError ? 0.08 : 0.0,
        })
      );

      const earthMesh = new THREE.Mesh(earthGeometry, earthMaterial);
      mainGroup.add(earthMesh);

      const atmosphereGeom = resourceManager.trackGeometry(
        new THREE.SphereGeometry(globeRadius * 1.08, segments, segments)
      );
      const atmosphereMat = resourceManager.trackMaterial(
        new THREE.MeshBasicMaterial({
          color: primaryColorHex,
          transparent: true,
          opacity: isLeak ? 0.25 : 0.15,
          side: THREE.BackSide,
        })
      );
      const atmosphereMesh = new THREE.Mesh(atmosphereGeom, atmosphereMat);
      mainGroup.add(atmosphereMesh);

      // Client Location Pin — ONLY rendered when finite, in-range GeoIP coordinates exist
      const clientPos =
        hasValidCoordinates ? latLonToVector3(validLat, validLon, globeRadius + 0.05) : null;

      if (clientPos) {
        const clientPinGroup = new THREE.Group();

        const pinStemGeom = resourceManager.trackGeometry(
          new THREE.CylinderGeometry(0.025, 0.025, 0.38, 12)
        );
        const pinStemMat = resourceManager.trackMaterial(
          new THREE.MeshPhysicalMaterial({
            color: primaryColorHex,
            emissive: primaryColorHex,
            emissiveIntensity: 0.5,
            metalness: 0.9,
          })
        );
        const pinStem = new THREE.Mesh(pinStemGeom, pinStemMat);
        pinStem.position.y = 0.19;

        const pinHeadGeom = resourceManager.trackGeometry(
          new THREE.SphereGeometry(0.09, 12, 12)
        );
        const pinHeadMat = resourceManager.trackMaterial(
          new THREE.MeshPhysicalMaterial({
            color: primaryColorHex,
            emissive: primaryColorHex,
            emissiveIntensity: 0.8,
            roughness: 0.1,
          })
        );
        const pinHead = new THREE.Mesh(pinHeadGeom, pinHeadMat);
        pinHead.position.y = 0.38;

        clientPinGroup.add(pinStem);
        clientPinGroup.add(pinHead);
        clientPinGroup.position.copy(clientPos);
        clientPinGroup.lookAt(ORIGIN_VECTOR);
        clientPinGroup.rotateX(Math.PI / 2);
        mainGroup.add(clientPinGroup);
      }
    } else {
      const shieldGroup = new THREE.Group();

      const shieldShape = new THREE.Shape();
      shieldShape.moveTo(0, 1.8);
      shieldShape.lineTo(1.4, 1.2);
      shieldShape.lineTo(1.4, -0.4);
      shieldShape.lineTo(0, -1.8);
      shieldShape.lineTo(-1.4, -0.4);
      shieldShape.lineTo(-1.4, 1.2);
      shieldShape.closePath();

      const extrudeSettings = {
        depth: 0.18,
        bevelEnabled: true,
        bevelSegments: isLowPowerOrSoftwareGl ? 2 : 3,
        steps: 1,
        bevelSize: 0.08,
        bevelThickness: 0.08,
      };
      const shieldGeom = resourceManager.trackGeometry(
        new THREE.ExtrudeGeometry(shieldShape, extrudeSettings)
      );
      const shieldMat = resourceManager.trackMaterial(
        new THREE.MeshPhysicalMaterial({
          color: primaryColorHex,
          emissive: primaryColorHex,
          emissiveIntensity: isLeak ? 0.6 : isError ? 0.35 : 0.2,
          metalness: 0.85,
          roughness: 0.15,
          clearcoat: 1.0,
        })
      );
      const shieldMesh = new THREE.Mesh(shieldGeom, shieldMat);
      shieldMesh.position.z = -0.08;
      shieldGroup.add(shieldMesh);

      const ringGeom = resourceManager.trackGeometry(
        new THREE.TorusGeometry(2.1, 0.04, 16, 48)
      );
      const ringMat = resourceManager.trackMaterial(
        new THREE.MeshPhysicalMaterial({
          color: primaryColorHex,
          emissive: primaryColorHex,
          emissiveIntensity: 0.7,
          metalness: 0.95,
        })
      );
      const ringMesh = new THREE.Mesh(ringGeom, ringMat);
      ringMesh.position.z = 0;
      shieldGroup.add(ringMesh);

      mainGroup.add(shieldGroup);
    }

    const startTimeMs = performance.now();
    let prevTimeMs = startTimeMs;

    const scheduleNextFrame = () => {
      if (resourceManager.isDisposed) return;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return;
      }
      if (isLowPowerOrSoftwareGl) {
        timeoutId = setTimeout(() => {
          if (!resourceManager.isDisposed) {
            animationFrameId = requestAnimationFrame(renderFrame);
          }
        }, 220);
      } else {
        animationFrameId = requestAnimationFrame(renderFrame);
      }
    };

    function renderFrame() {
      if (resourceManager.isDisposed || !controls) return;
      const nowMs = performance.now();
      const delta = Math.min(0.1, (nowMs - prevTimeMs) / 1000);
      prevTimeMs = nowMs;
      const time = (nowMs - startTimeMs) / 1000;
      controls.update();

      mainGroup.rotation.y += delta * (isLeak ? 0.4 : 0.18);
      alarmRingMesh.rotation.z += delta * 0.5;

      if (isLeak) {
        alarmRingMesh.scale.setScalar(1 + Math.sin(time * 6) * 0.08);
      } else {
        alarmRingMesh.scale.setScalar(1);
      }

      renderer.render(scene, camera);
      scheduleNextFrame();
    }

    const handleContextLost = (event: Event) => {
      event.preventDefault();
      if (animationFrameId !== null) {
        cancelAnimationFrame(animationFrameId);
        animationFrameId = null;
      }
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      setWebglUnavailable(true);
    };

    const handleVisibilityChange = () => {
      if (resourceManager.isDisposed) return;
      if (document.visibilityState === 'hidden') {
        if (animationFrameId !== null) {
          cancelAnimationFrame(animationFrameId);
          animationFrameId = null;
        }
        if (timeoutId !== null) {
          clearTimeout(timeoutId);
          timeoutId = null;
        }
      } else if (animationFrameId === null && timeoutId === null) {
        prevTimeMs = performance.now();
        scheduleNextFrame();
      }
    };

    const updateViewportSize = (newW: number, newH: number) => {
      if (resourceManager.isDisposed) return;
      const safeW = Math.floor(newW);
      const safeH = Math.floor(newH);
      if (safeW <= 0 || safeH <= 0) return;
      if (safeW === lastWidth && safeH === lastHeight) return;

      lastWidth = safeW;
      lastHeight = safeH;
      camera.aspect = safeW / safeH;
      camera.updateProjectionMatrix();
      renderer.setSize(safeW, safeH, false);
    };

    const handleWindowResize = () => {
      if (!container) return;
      updateViewportSize(container.clientWidth, container.clientHeight);
    };

    if (typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(entries => {
        for (const entry of entries) {
          const { width: observedW, height: observedH } = entry.contentRect;
          updateViewportSize(observedW, observedH);
        }
      });
      resizeObserver.observe(container);
    }

    const canvasElem = renderer.domElement;
    canvasElem.addEventListener('webglcontextlost', handleContextLost, false);
    window.addEventListener('resize', handleWindowResize);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    renderFrame();

    return () => {
      canvasElem.removeEventListener('webglcontextlost', handleContextLost, false);
      window.removeEventListener('resize', handleWindowResize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);

      resourceManager.collectFromScene(scene);
      scene.environment = null;
      scene.clear();

      resourceManager.disposeAll({
        animationFrameId,
        timeoutId,
        resizeObserver,
        controls,
        pmremGenerator,
        roomEnvironment,
        renderer,
        container,
      });
    };
  }, [
    mode,
    visualCategory,
    isLeak,
    isError,
    isPass,
    hasValidCoordinates,
    validLat,
    validLon,
  ]);

  const badgeText = isFa ? statusInfo.badgeTextFa : statusInfo.badgeTextEn;

  const badgeClasses = isLeak
    ? 'bg-rose-950/90 text-rose-200 border-rose-800/80 shadow-rose-900/50'
    : isError
    ? 'bg-orange-950/90 text-orange-200 border-orange-800/80 shadow-orange-900/50'
    : isPass
    ? 'bg-emerald-950/90 text-emerald-200 border-emerald-800/80 shadow-emerald-900/50'
    : 'bg-amber-950/90 text-amber-200 border-amber-800/80 shadow-amber-900/50';

  return (
    <div
      className={`relative bg-gradient-to-b ${
        isLeak
          ? 'from-rose-950/40 via-slate-950 to-slate-950 border-rose-800/80 shadow-[0_0_40px_rgba(239,68,68,0.2)]'
          : isError
          ? 'from-orange-950/30 via-slate-950 to-slate-950 border-orange-800/70 shadow-2xl'
          : 'from-slate-900 to-slate-950 border-slate-800 shadow-2xl'
      } border rounded-3xl overflow-hidden transition-all duration-300 ${
        isExpanded ? 'h-[620px]' : 'h-[420px]'
      }`}
    >
      {/* WebGL 3D Canvas or Graceful Non-WebGL Fallback */}
      {webglUnavailable ? (
        <div className="w-full h-full flex flex-col items-center justify-center px-6 text-center bg-slate-950/90">
          <MonitorOff className="w-10 h-10 text-amber-400 mb-3" />
          <p className="text-sm font-bold text-slate-200 mb-1">
            {isFa
              ? 'پیش‌نمایش سه‌بعدی (WebGL) در این مرورگر یا پردازنده گرافیکی در دسترس نیست'
              : '3D Visualization (WebGL) is unavailable on this browser or GPU'}
          </p>
          <p className="text-xs text-slate-400 max-w-md leading-relaxed">
            {isFa
              ? 'عدم پشتیبانی از WebGL هیچ تأثیری بر دقت تست‌های شبکه ندارد. نتایج واقعی در کارت‌های پایین صفحه قابل مشاهده است.'
              : 'WebGL unavailability does not affect network probe accuracy. Real test results are available in the diagnostic cards below.'}
          </p>
        </div>
      ) : (
        <div
          ref={mountRef}
          className="w-full h-full cursor-grab active:cursor-grabbing"
        />
      )}

      {/* Dynamic 3D Status Overlay Banner */}
      <div className="absolute top-4 right-4 left-4 flex flex-wrap items-center justify-between gap-2 pointer-events-none z-20">
        <div
          className={`flex items-center gap-2.5 px-4 py-2 rounded-2xl border font-bold text-xs pointer-events-auto shadow-2xl ${badgeClasses}`}
        >
          {isLeak ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : isError ? (
            <AlertOctagon className="w-4 h-4 text-orange-400 shrink-0" />
          ) : isPass ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
          )}
          <span>{badgeText}</span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 pointer-events-auto">
          <div className="bg-slate-950/90 p-1 rounded-2xl border border-slate-800 flex items-center gap-1 shadow-lg">
            <button
              type="button"
              onClick={() => setMode('globe')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                mode === 'globe'
                  ? 'bg-cyan-500 text-slate-950 shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <GlobeIcon className="w-3.5 h-3.5" />
              <span>{isFa ? 'کره زمین' : 'Globe'}</span>
            </button>

            <button
              type="button"
              onClick={() => setMode('shield')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                mode === 'shield'
                  ? isLeak
                    ? 'bg-rose-500 text-slate-950 shadow-md'
                    : isError
                    ? 'bg-orange-500 text-slate-950 shadow-md'
                    : isPass
                    ? 'bg-emerald-500 text-slate-950 shadow-md'
                    : 'bg-amber-500 text-slate-950 shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>{isFa ? 'سپر ۳D' : '3D Shield'}</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setIsExpanded(prev => !prev)}
            aria-label={isFa ? 'تغییر اندازه نمای سه‌بعدی' : 'Toggle 3D view size'}
            className="bg-slate-950/90 text-slate-300 hover:text-white p-2 rounded-2xl border border-slate-800 transition-colors shadow-lg cursor-pointer"
          >
            {isExpanded ? (
              <Minimize2 className="w-4 h-4" />
            ) : (
              <Maximize2 className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>

      {/* Bottom Information Bar */}
      <div className="absolute bottom-4 right-4 left-4 flex flex-wrap items-center justify-between gap-2 bg-slate-950/90 px-4 py-2.5 rounded-2xl border border-slate-800 text-xs shadow-xl">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Radio
              className={`w-4 h-4 ${
                isLeak
                  ? 'text-rose-400'
                  : isError
                  ? 'text-orange-400'
                  : isPass
                  ? 'text-emerald-400'
                  : 'text-amber-400'
              }`}
            />
            <span className="text-slate-300 font-medium">
              {isFa ? 'مکان پین سه بعدی:' : '3D Pin Location:'}
            </span>
            <span className="font-mono font-bold text-slate-200">
              {hasValidCoordinates &&
              typeof validLat === 'number' &&
              typeof validLon === 'number'
                ? isFa
                  ? `تخمین پایگاه GeoIP (${validLat.toFixed(2)}, ${validLon.toFixed(2)})`
                  : `GeoIP Estimate (${validLat.toFixed(2)}, ${validLon.toFixed(2)})`
                : isFa
                ? 'مختصات جغرافیایی معتبر موجود نیست — پین ترسیم نشد'
                : 'Valid coordinates unavailable — No pin plotted'}
            </span>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-slate-400 text-[11px]">
          <Compass className="w-3.5 h-3.5 text-cyan-400" />
          <span>
            {isFa
              ? 'نمای گرافیکی • برای چرخش ماوس را درگ کنید'
              : 'Graphical view • Drag to rotate 3D model'}
          </span>
        </div>
      </div>
    </div>
  );
};
