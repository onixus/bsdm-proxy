import { Activity, AlertTriangle, Clock, Database, ShieldCheck, Zap } from 'lucide-react'
import { formatUptime, type Telemetry } from '../../../api/metrics'
import { formatNumber, seriesColor } from '../../charts/common'
import { StatTile, WidgetGrid } from '../MetricWidget'
import { translations, type Language } from '../../../lib/i18n'

interface HealthOverviewProps