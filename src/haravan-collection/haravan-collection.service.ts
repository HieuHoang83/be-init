import { Injectable } from '@nestjs/common';
import { HaravanOmniService } from '../api/haravan-omni.service';

@Injectable()
export class HaravanCollectionService extends HaravanOmniService {}
