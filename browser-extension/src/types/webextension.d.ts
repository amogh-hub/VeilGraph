declare namespace chrome {
  namespace runtime {
    interface MessageSender {
      tab?: tabs.Tab
      frameId?: number
      url?: string
    }
    type SendResponse = (response?: unknown) => void
    const onMessage: {
      addListener(
        callback: (message: unknown, sender: MessageSender, sendResponse: SendResponse) => boolean | void,
      ): void
    }
    function sendMessage<T = unknown>(message: unknown): Promise<T>
    function getURL(path: string): string
  }

  namespace tabs {
    interface Tab { id?: number; windowId?: number; url?: string; active?: boolean }
    function query(queryInfo: { active?: boolean; currentWindow?: boolean }): Promise<Tab[]>
    function sendMessage<T = unknown>(tabId: number, message: unknown, options?: { frameId?: number }): Promise<T>
    function captureVisibleTab(windowId?: number, options?: { format?: 'png' | 'jpeg'; quality?: number }): Promise<string>
  }

  namespace webNavigation {
    interface GetAllFrameResultDetails { frameId: number; parentFrameId: number; url: string }
    function getAllFrames(details: { tabId: number }): Promise<GetAllFrameResultDetails[] | null>
  }

  namespace storage {
    interface StorageArea {
      get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>
      set(items: Record<string, unknown>): Promise<void>
    }
    const local: StorageArea
    const session: StorageArea
  }

  namespace sidePanel {
    function open(options: { tabId?: number; windowId?: number }): Promise<void>
  }

  namespace action {
    const onClicked: { addListener(callback: (tab: tabs.Tab) => void): void }
  }

  namespace permissions {
    function contains(permissions: { origins?: string[] }): Promise<boolean>
    function request(permissions: { origins?: string[] }): Promise<boolean>
  }
}

interface BarcodeDetectorOptions { formats?: string[] }
interface DetectedBarcode { boundingBox: DOMRectReadOnly; rawValue: string }
declare class BarcodeDetector {
  constructor(options?: BarcodeDetectorOptions)
  detect(source: ImageBitmapSource): Promise<DetectedBarcode[]>
}

interface FaceDetectorOptions { fastMode?: boolean; maxDetectedFaces?: number }
interface DetectedFace { boundingBox: DOMRectReadOnly }
declare class FaceDetector {
  constructor(options?: FaceDetectorOptions)
  detect(source: ImageBitmapSource): Promise<DetectedFace[]>
}

interface DetectedText { boundingBox: DOMRectReadOnly; rawValue?: string }
declare class TextDetector {
  constructor()
  detect(source: ImageBitmapSource): Promise<DetectedText[]>
}
