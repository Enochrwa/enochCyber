# packet_sniffer_events.py
import socketio
import logging
import asyncio
from multiprocessing import Queue
from typing import Any, Dict
import csv # Added
import io  # Added
import json # Added

logger = logging.getLogger(__name__)


class PacketSnifferNamespace(socketio.AsyncNamespace): # Changed
    def __init__(self, namespace: str, sio_queue: Queue, app_state: Any): # Changed
        super().__init__(namespace)
        self.sio_queue = sio_queue
        self.app_state = app_state # Added
        self.current_interface = None # Added
        # sid_for_client will be set in on_connect for emitting back to a specific client
        self.sid_for_client: str | None = None  # Added
        # Manage queue processing state
        self.is_processing_queue = False  # Added
        self.stop_processing_event = asyncio.Event() # Added


    async def on_connect(self, sid: str, environ: Dict[str, Any]): # Added
        logger.info(f"Client {sid} connected to PacketSnifferNamespace.")
        self.sid_for_client = sid # Store client's SID

        # Start a queue listener task if not already running.
        # This simple model assumes one listener for the namespace instance.
        # If multiple clients connect, they share this listener.
        if not self.is_processing_queue:
            self.stop_processing_event.clear() # Clear event before starting listener
            asyncio.create_task(self._queue_listener())
            logger.info(f"PacketSnifferNamespace: Started queue listener for client {sid}.")


    async def _queue_listener(self): # Added
        """
        Listens to the sio_queue and emits messages.
        If self.sid_for_client is set, it emits only to that client.
        Otherwise, it might log or decide not to emit.
        """
        self.is_processing_queue = True
        logger.info("PacketSnifferNamespace: Queue listener now active.")
        while not self.stop_processing_event.is_set():
            try:
                if self.sio_queue.empty():
                    await asyncio.sleep(0.01) # Wait for messages
                    continue

                # Assuming message is a tuple: (event_type, data)
                # Use get_nowait() or handle queue.Empty for non-blocking get
                message = self.sio_queue.get_nowait()
                event_type, data = message

                if self.sid_for_client: # Emit to the stored SID if available
                    await self.emit(event_type, data, to=self.sid_for_client)
                    logger.debug(f"PacketSnifferNamespace: Emitted {event_type} to {self.sid_for_client}")
                else:
                    # Fallback if no specific client SID is targeted (e.g. broadcast or log)
                    # await self.emit(event_type, data) # Example: broadcast to namespace
                    logger.debug(f"PacketSnifferNamespace: Received {event_type}, but no specific client SID to emit to. Consider broadcasting or logging.")

            except asyncio.QueueEmpty: # Specific exception for asyncio.Queue
                await asyncio.sleep(0.01) # Wait if queue is empty
            except Exception as e: # Catch other exceptions
                logger.error(f"PacketSnifferNamespace: Error in queue listener: {e}", exc_info=True)
                await asyncio.sleep(0.1) # Brief pause after an error
        
        self.is_processing_queue = False # Mark as not processing
        logger.info("PacketSnifferNamespace: Queue listener stopped.")


    async def on_disconnect(self, sid: str): # Added
        logger.info(f"Client {sid} disconnected from PacketSnifferNamespace.")
        # If the disconnected client is the one we're tracking, clear its SID
        if sid == self.sid_for_client:
            self.sid_for_client = None
            # Optionally, stop the queue listener if it's only for this client
            # or if no other clients are connected (more complex logic needed for that).
            # For this example, we'll signal it to stop if the tracked client disconnects.
            if self.is_processing_queue:
                 self.stop_processing_event.set()
                 logger.info("PacketSnifferNamespace: Signaling queue listener to stop due to client disconnect.")


    async def on_select_interface(self, sid: str, data: Any): # Added
        interface_name = data if isinstance(data, str) else data.get("interface")
        if not interface_name:
            logger.warning(f"Client {sid} sent invalid interface selection data: {data}")
            try:
                await self.emit('interface_selected_status', {'status': 'error', 'message': 'No interface name provided'}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting interface_selected_status (invalid data): {e_emit}", exc_info=True)
            return

        logger.info(f"Client {sid} selected interface: {interface_name}")
        sniffer = None
        sniffer_service = None
        try:
            if not hasattr(self, 'app_state') or self.app_state is None:
                logger.error("app_state not initialized in PacketSnifferNamespace.")
                try:
                    await self.emit('interface_selected_status', {'status': 'error', 'message': 'Server configuration error: app_state missing.'}, to=sid)
                except Exception as e_emit:
                    logger.error(f"Error emitting interface_selected_status (app_state missing): {e_emit}", exc_info=True)
                return
            sniffer = self.app_state.sniffer
            sniffer_service = self.app_state.sniffer_service
        except AttributeError:
            logger.error("Sniffer or SnifferService not found in app_state. Ensure they are correctly populated.")
            try:
                await self.emit('interface_selected_status', {'status': 'error', 'message': 'Sniffer components not configured on server'}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting interface_selected_status (AttributeError): {e_emit}", exc_info=True)
            return

        if sniffer:
            try:
                if sniffer_service: # Clear previous packets before starting new capture
                    await sniffer_service.clear_exportable_packets()
                else:
                    logger.warning("SnifferService not available, cannot clear previous packets for export.")

                logger.info(f"Attempting to switch sniffer to interface: {interface_name}")
                await sniffer.start(interface_name)
                self.current_interface = interface_name
                logger.info(f"Sniffer presumably switched to new interface: {interface_name}")
                try:
                    await self.emit('interface_selected_status', {'status': 'success', 'interface': interface_name}, to=sid)
                except Exception as e_emit:
                    logger.error(f"Error emitting interface_selected_status (success): {e_emit}", exc_info=True)
            except Exception as e:
                logger.error(f"Error restarting sniffer for interface {interface_name}: {e}", exc_info=True)
                try:
                    await self.emit('interface_selected_status', {'status': 'error', 'message': str(e)}, to=sid)
                except Exception as em_e:
                    logger.error(f"Error emitting interface_selected_status (sniffer start error): {em_e}", exc_info=True)
        else:
            logger.error("Sniffer instance is None (retrieved from app_state), cannot select interface.")
            try:
                await self.emit('interface_selected_status', {'status': 'error', 'message': 'Sniffer not initialized on server (is None)'}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting interface_selected_status (sniffer is None): {e_emit}", exc_info=True)

    async def on_stop_sniffing(self, sid):
        logger.info(f"Client {sid} requested to stop sniffing.")
        sniffer = None
        sniffer_service = None
        try:
            sniffer = self.app_state.sniffer
            sniffer_service = self.app_state.sniffer_service
        except AttributeError:
            logger.error("Sniffer or SnifferService not found in app_state during stop_sniffing.")
            try:
                await self.emit('sniffer_status', {'status': 'error', 'message': 'Sniffer components not found on server.'}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting sniffer_status (AttributeError): {e_emit}", exc_info=True)
            return

        if sniffer:
            try:
                sniffer.stop() # This is synchronous
                logger.info("Sniffer stopped by client request.")
                if sniffer_service:
                    await sniffer_service.clear_exportable_packets()
                await self.emit('sniffer_status', {'status': 'stopped', 'interface': self.current_interface}, to=sid)
                self.current_interface = None
            except Exception as e_stop:
                logger.error(f"Error during sniffer stop or status emission: {e_stop}", exc_info=True)
                try:
                    await self.emit('sniffer_status', {'status': 'error', 'message': f'Error stopping sniffer: {e_stop}'}, to=sid)
                except Exception as e_emit_err:
                     logger.error(f"Error emitting sniffer_status (stop error): {e_emit_err}", exc_info=True)
        else:
            logger.error("Sniffer not found, cannot stop.")
            try:
                await self.emit('sniffer_status', {'status': 'error', 'message': 'Sniffer not found'}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting sniffer_status (sniffer not found): {e_emit}", exc_info=True)

    async def on_request_export_packets(self, sid, params):
        export_format = params.get("format", "json")
        logger.info(f"Client {sid} requested packet export in {export_format} format.")

        sniffer_service = None
        try:
            sniffer_service = self.app_state.sniffer_service
        except AttributeError:
            logger.error("SnifferService not found in app_state for export.")
            try:
                await self.emit("export_data_response", {"error": "Sniffer service not available."}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting export_data_response (SnifferService missing): {e_emit}", exc_info=True)
            return

        if not sniffer_service:
            try:
                await self.emit("export_data_response", {"error": "Sniffer service not initialized."}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting export_data_response (SnifferService not init): {e_emit}", exc_info=True)
            return

        packets = await sniffer_service.get_packets_for_export()

        if not packets:
            try:
                await self.emit("export_data_response", {"error": "No packets available for export."}, to=sid)
            except Exception as e_emit:
                logger.error(f"Error emitting export_data_response (no packets): {e_emit}", exc_info=True)
            return

        try:
            if export_format == "csv":
                output = io.StringIO()
                headers = ["timestamp", "source_ip", "destination_ip", "protocol", "bytes_transferred", "host", "path", "method", "user_agent", "suspicious_headers", "risk_score", "blocked"]
                writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore', quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows(packets)
                formatted_data = output.getvalue()
                output.close()
                await self.emit("export_data_response", {"format": "csv", "data": formatted_data}, to=sid)
            elif export_format == "json":
                formatted_data = json.dumps(packets, indent=2)
                await self.emit("export_data_response", {"format": "json", "data": formatted_data}, to=sid)
            else:
                await self.emit("export_data_response", {"error": "Unsupported export format."}, to=sid)
            logger.info(f"Sent {len(packets)} packets in {export_format} format to client {sid}.")
        except Exception as e:
            logger.error(f"Error formatting or sending export data: {e}", exc_info=True)
            try:
                await self.emit("export_data_response", {"error": f"Failed to export data: {str(e)}"}, to=sid)
            except Exception as e_emit:
                 logger.error(f"Error emitting export_data_response (formatting error): {e_emit}", exc_info=True)