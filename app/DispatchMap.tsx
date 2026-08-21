"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./map.css";

type MapVehicle = { id: string; name: string; type: string; status: string; coords: [number, number] };

export default function DispatchMap({ center, vehicles }: { center: [number, number]; vehicles: MapVehicle[] }) {
  const element = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const incidentMarker = useRef<L.Marker | null>(null);
  const vehicleMarkers = useRef<Map<string, L.Marker>>(new Map());

  useEffect(() => {
    if (!element.current || map.current) return;
    const instance = L.map(element.current).setView(center, 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    }).addTo(instance);
    map.current = instance;
    return () => { instance.remove(); map.current = null; incidentMarker.current = null; vehicleMarkers.current.clear() };
  }, []);

  useEffect(() => {
    if (!map.current) return;
    const icon = L.divIcon({ className: "incident-leaflet-icon", html: "<span><b>!</b></span>", iconSize: [38, 45], iconAnchor: [19, 45] });
    if (incidentMarker.current) incidentMarker.current.setLatLng(center).setIcon(icon);
    else incidentMarker.current = L.marker(center, { icon, zIndexOffset: 1000 }).addTo(map.current);
    map.current.setView(center, map.current.getZoom(), { animate: false });
  }, [center[0], center[1]]);

  useEffect(() => {
    if (!map.current) return;
    const active = new Set(vehicles.map(vehicle => vehicle.id));
    vehicleMarkers.current.forEach((marker, id) => { if (!active.has(id)) { marker.remove(); vehicleMarkers.current.delete(id) } });
    vehicles.forEach(vehicle => {
      const icon = L.divIcon({ className: "vehicle-leaflet-icon", html: `<i>${vehicle.type}</i><span><b>${vehicle.name}</b><small>${vehicle.status}</small></span>`, iconSize: [165, 38], iconAnchor: [18, 19] });
      const existing = vehicleMarkers.current.get(vehicle.id);
      if (existing) existing.setLatLng(vehicle.coords).setIcon(icon);
      else vehicleMarkers.current.set(vehicle.id, L.marker(vehicle.coords, { icon, zIndexOffset: 500 }).addTo(map.current!));
    });
  }, [vehicles]);

  return <div ref={element} className="dispatch-map" aria-label="Interaktive Einsatzkarte" />;
}
