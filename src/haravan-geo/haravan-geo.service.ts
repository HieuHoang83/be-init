import { Injectable } from '@nestjs/common';
import { HaravanOmniService } from '../api/haravan-omni.service';

@Injectable()
export class HaravanGeoService extends HaravanOmniService {}
